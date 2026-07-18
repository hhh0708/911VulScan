#!/usr/bin/env bash
# =============================================================================
# 911VulScan 新机器一键部署（自适应路径，开箱即用）
#
# 放置方式（二选一）:
#   A) 与 911VulScan 源码同目录:
#        ~/Desktop/911VulScan/
#        ~/Desktop/deploy_911vulscan.sh
#   B) 放在 911VulScan 根目录内:
#        ~/Desktop/911VulScan/deploy_911vulscan.sh
#
# 用法:
#   chmod +x deploy_911vulscan.sh
#   ./deploy_911vulscan.sh
#
# 部署完成后新开终端即可直接使用 vulscan，无需再 source 任何脚本。
# =============================================================================

set -euo pipefail

# --- 固定配置（与 run_test.sh 一致）---
GO_VERSION="${GO_VERSION:-1.25.7}"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"
CONDA_ENV_NAME="${VULSCAN_PYTHON_ENV:-vulscan-py311}"
MINICONDA_DIR="${MINICONDA_DIR:-${HOME}/miniconda3}"
PYTHON_SOURCE=""          # system | conda（安装后填充）
CONDA_ROOT=""             # conda 根目录（conda 路径时填充）
CONDA_ENV_DIR=""          # py3.11 环境目录（conda 路径时填充）
NODE_VERSION="${NODE_VERSION:-v20.19.2}"
# LLM settings come from the environment or an interactive silent prompt.
# Never hardcode API keys or provider/model defaults in this script.
VULSCAN_LLM_PROVIDER="${VULSCAN_LLM_PROVIDER:-}"
VULSCAN_LLM_MODEL="${VULSCAN_LLM_MODEL:-}"
VULSCAN_LLM_BASE_URL="${VULSCAN_LLM_BASE_URL:-}"
# Resolved at configure_llm time; never written into the git repo.
_LLM_API_KEY=""

CONFIG_DIR="${HOME}/.config/911vulscan"
ENV_FILE="${CONFIG_DIR}/env.sh"
PROXY_ENV_FILE="${CONFIG_DIR}/proxy.env"
LLM_ENV_FILE="${CONFIG_DIR}/llm.env"
BASHRC_MARKER_BEGIN="# >>> 911VulScan environment (managed by deploy_911vulscan.sh) >>>"
BASHRC_MARKER_END="# <<< 911VulScan environment <<<"
DEFAULT_NO_PROXY="localhost,127.0.0.1,::1,172.17.0.0/16,172.18.0.0/16"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULSCAN_ROOT=""
CLI_DIR=""
VULSCAN_BIN=""
NODE_DIR="${HOME}/.local/node"
PROXY_URL=""

log()  { echo; echo "============================================================"; echo "$*"; echo "============================================================"; }
info() { echo "  ✓ $*"; }
warn() { echo "  ! $*"; }
die()  { echo "错误: $*" >&2; exit 1; }

need_sudo() {
  if ! sudo -n true 2>/dev/null; then
    echo "部分步骤需要 sudo（apt / docker / /usr/local/bin），请输入密码:"
    sudo -v || die "需要 sudo 权限"
  fi
}

# ---------------------------------------------------------------------------
# 路径自适应
# ---------------------------------------------------------------------------
resolve_vulscan_root() {
  if [[ -d "${SCRIPT_DIR}/libs/vulscan-core" ]]; then
    VULSCAN_ROOT="${SCRIPT_DIR}"
  elif [[ -d "${SCRIPT_DIR}/911VulScan/libs/vulscan-core" ]]; then
    VULSCAN_ROOT="${SCRIPT_DIR}/911VulScan"
  else
    die "未找到 911VulScan 源码。请将本脚本与 911VulScan 放在同一目录，或放在 911VulScan 根目录内。"
  fi
  CLI_DIR="${VULSCAN_ROOT}/apps/vulscan-cli"
  VULSCAN_BIN="${CLI_DIR}/bin/vulscan"
  info "源码目录: ${VULSCAN_ROOT}"
}

normalize_proxy_url() {
  local ip="$1" port="$2"
  ip="${ip#http://}"
  ip="${ip#https://}"
  ip="${ip%/}"
  if [[ "$ip" =~ : ]]; then
    echo "http://${ip}"
  else
    echo "http://${ip}:${port}"
  fi
}

read_proxy_from_user() {
  local ip port
  echo
  echo "=== 代理配置（部署过程仅需输入一次）==="
  read -r -p "代理 IP (例如 192.168.31.141): " ip
  [[ -n "$ip" ]] || die "代理 IP 不能为空"
  read -r -p "代理端口 [7897]: " port
  port="${port:-7897}"
  PROXY_URL="$(normalize_proxy_url "$ip" "$port")"
  info "将使用代理: ${PROXY_URL}"
}

source_proxy_env() {
  # shellcheck disable=SC1091
  [[ -f "${PROXY_ENV_FILE}" ]] && source "${PROXY_ENV_FILE}"
}

python311_ready() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || return 1
  "$bin" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)' 2>/dev/null
}

find_conda_root() {
  if command -v conda >/dev/null 2>&1; then
    CONDA_ROOT="$(conda info --base 2>/dev/null || true)"
    if [[ -n "${CONDA_ROOT}" && -x "${CONDA_ROOT}/bin/conda" ]]; then
      return 0
    fi
    CONDA_ROOT=""
  fi
  local candidate
  for candidate in "${MINICONDA_DIR}" "${HOME}/miniconda3" "${HOME}/anaconda3" "${HOME}/mambaforge"; do
    if [[ -x "${candidate}/bin/conda" ]]; then
      CONDA_ROOT="${candidate}"
      return 0
    fi
  done
  return 1
}

activate_conda_shell() {
  [[ -n "${CONDA_ROOT}" ]] || return 1
  # shellcheck disable=SC1091
  source "${CONDA_ROOT}/etc/profile.d/conda.sh"
}

install_miniconda() {
  log "通过 Miniconda 安装 Python 3.11（apt 不可用时的回退方案）"

  local arch installer url
  case "$(uname -m)" in
    x86_64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac

  installer="Miniconda3-latest-Linux-${arch}.sh"
  url="https://repo.anaconda.com/miniconda/${installer}"

  echo "下载 ${url} ..."
  local tmpdir
  tmpdir="$(mktemp -d)"
  source_proxy_env
  curl -fsSL "$url" -o "${tmpdir}/${installer}"
  bash "${tmpdir}/${installer}" -b -p "${MINICONDA_DIR}"
  rm -rf "$tmpdir"

  CONDA_ROOT="${MINICONDA_DIR}"
  activate_conda_shell
  info "Miniconda 已安装: ${CONDA_ROOT}"
}

ensure_conda_python311_env() {
  if ! find_conda_root; then
    install_miniconda
  else
    info "检测到 Conda: ${CONDA_ROOT}"
    activate_conda_shell
  fi

  if conda env list | awk '{print $1}' | grep -Fxq "${CONDA_ENV_NAME}"; then
    info "复用已有 Conda 环境: ${CONDA_ENV_NAME}"
  else
    echo "创建 Conda 环境 ${CONDA_ENV_NAME} (Python 3.11) ..."
    source_proxy_env
    conda create -n "${CONDA_ENV_NAME}" python=3.11 pip setuptools wheel -y
  fi

  CONDA_ENV_DIR="${CONDA_ROOT}/envs/${CONDA_ENV_NAME}"
  [[ -x "${CONDA_ENV_DIR}/bin/python" ]] || die "Conda 环境创建失败: ${CONDA_ENV_DIR}"

  # 兼容脚本里对 python3.11 命令名的检查
  ln -sf python "${CONDA_ENV_DIR}/bin/python3.11"
  ln -sf python "${CONDA_ENV_DIR}/bin/python3"

  PYTHON_BIN="${CONDA_ENV_DIR}/bin/python3.11"
  PYTHON_SOURCE="conda"
  export PATH="${CONDA_ENV_DIR}/bin:${CONDA_ROOT}/bin:${PATH}"
  info "Conda Python: $("${PYTHON_BIN}" --version) @ ${CONDA_ENV_DIR}"
}

install_python311_apt() {
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update
  sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
}

install_python() {
  if python311_ready "$PYTHON_BIN"; then
    PYTHON_SOURCE="system"
    info "Python 已就绪: $($PYTHON_BIN --version)"
    return 0
  fi

  echo "安装 Python 3.11（优先 apt，失败则回退 Miniconda）..."
  if install_python311_apt; then
    PYTHON_BIN="python3.11"
    PYTHON_SOURCE="system"
    info "Python (apt): $($PYTHON_BIN --version)"
    return 0
  fi

  warn "apt 无法安装 python3.11（常见于 Ubuntu 20.04），改用 Miniconda"
  ensure_conda_python311_env
}

configure_default_python_env() {
  [[ "${PYTHON_SOURCE}" == "conda" ]] || return 0

  # 当前部署进程立即生效
  export PATH="${CONDA_ENV_DIR}/bin:${CONDA_ROOT}/bin:${PATH}"
  hash -r 2>/dev/null || true

  # 持久化 conda 初始化（新终端默认可用 conda / 默认 py3.11 环境）
  if [[ -f "${HOME}/.bashrc" ]] && ! grep -qF 'conda initialize' "${HOME}/.bashrc" 2>/dev/null; then
    activate_conda_shell || true
    conda init bash >/dev/null 2>&1 || true
  fi

  info "默认 Python 环境: conda activate ${CONDA_ENV_NAME}"
}

# ---------------------------------------------------------------------------
# Step 1: 系统依赖
# ---------------------------------------------------------------------------
install_system_deps() {
  log "Step 1/8: 安装系统依赖 (Python ${PYTHON_BIN#python} / Go / Docker)"

  need_sudo
  sudo apt-get update
  sudo apt-get install -y \
    ca-certificates curl wget git jq unzip tar xz-utils \
    build-essential pkg-config make gcc g++ \
    software-properties-common gnupg lsb-release

  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1 || ! python311_ready "$PYTHON_BIN"; then
    install_python
  else
    PYTHON_SOURCE="system"
    info "Python: $($PYTHON_BIN --version)"
  fi
  configure_default_python_env
  info "Python 来源: ${PYTHON_SOURCE:-unknown} | 解释器: ${PYTHON_BIN}"

  export PATH="/usr/local/go/bin:${PATH}"
  if ! command -v go >/dev/null 2>&1 || ! go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    echo "安装 Go ${GO_VERSION} ..."
    cd /tmp
    rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
  fi
  export PATH="/usr/local/go/bin:${PATH}"
  info "Go: $(go version)"

  if ! command -v docker >/dev/null 2>&1; then
    echo "安装 Docker ..."
    sudo apt-get install -y docker.io
  fi
  sudo systemctl enable docker >/dev/null 2>&1 || true
  sudo systemctl start docker >/dev/null 2>&1 || true
  info "Docker: $(docker --version 2>/dev/null || echo unknown)"

  if ! groups "$USER" | grep -qw docker; then
    sudo usermod -aG docker "$USER"
    warn "已将 ${USER} 加入 docker 组；若 docker ps 失败，请重新登录或执行 newgrp docker"
  fi
}

# ---------------------------------------------------------------------------
# Step 2: Node.js 20 LTS
# ---------------------------------------------------------------------------
install_node() {
  log "Step 2/8: 安装 Node.js ${NODE_VERSION} (JS/TS 解析必需)"

  local arch tarball url
  case "$(uname -m)" in
    x86_64) arch="linux-x64" ;;
    aarch64|arm64) arch="linux-arm64" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac

  tarball="node-${NODE_VERSION}-${arch}.tar.xz"
  url="https://nodejs.org/dist/${NODE_VERSION}/${tarball}"

  if [[ -x "${NODE_DIR}/bin/node" ]] && "${NODE_DIR}/bin/node" --version | grep -q "^v20\\."; then
    info "Node 已安装: $("${NODE_DIR}/bin/node" --version)"
    return 0
  fi

  echo "下载 ${url} ..."
  local tmpdir
  tmpdir="$(mktemp -d)"
  curl -fsSL "$url" -o "${tmpdir}/${tarball}"
  rm -rf "$NODE_DIR"
  mkdir -p "${HOME}/.local"
  tar -xJf "${tmpdir}/${tarball}" -C "${HOME}/.local"
  mv "${HOME}/.local/node-${NODE_VERSION}-${arch}" "$NODE_DIR"
  rm -rf "$tmpdir"
  info "Node: $("${NODE_DIR}/bin/node" --version)"
  info "npm:  $("${NODE_DIR}/bin/npm" --version)"
}

# ---------------------------------------------------------------------------
# Step 3: 编译 vulscan CLI
# ---------------------------------------------------------------------------
build_vulscan() {
  log "Step 3/8: 编译 vulscan CLI"

  [[ -d "$CLI_DIR" ]] || die "未找到 ${CLI_DIR}"
  export PATH="/usr/local/go/bin:${PATH}"
  cd "$CLI_DIR"
  make build
  [[ -x "$VULSCAN_BIN" ]] || die "编译失败: ${VULSCAN_BIN}"
  info "已生成: ${VULSCAN_BIN}"

  # 移除可能遮蔽 Go CLI 的 Python/conda 版 vulscan
  local py
  for py in "${PYTHON_BIN}" python3.11 python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
      "$py" -m pip uninstall -y vulscan 2>/dev/null || true
    fi
  done
  if [[ -n "${CONDA_ENV_DIR}" && -x "${CONDA_ENV_DIR}/bin/python" ]]; then
    "${CONDA_ENV_DIR}/bin/python" -m pip uninstall -y vulscan 2>/dev/null || true
  fi
  for f in "${HOME}/miniconda3/bin/vulscan" "${HOME}/anaconda3/bin/vulscan" \
           "${HOME}/miniconda3/envs/"*/bin/vulscan; do
    [[ -e "$f" ]] || continue
    if [[ "$(readlink -f "$f" 2>/dev/null || echo "$f")" != "$(readlink -f "$VULSCAN_BIN")" ]]; then
      rm -f "$f" 2>/dev/null || true
    fi
  done

  need_sudo
  sudo ln -sf "$VULSCAN_BIN" /usr/local/bin/vulscan
  info "已软链: /usr/local/bin/vulscan -> ${VULSCAN_BIN}"
}

# ---------------------------------------------------------------------------
# Step 4: 代理（Shell + Docker）
# ---------------------------------------------------------------------------
write_proxy_env() {
  mkdir -p "$CONFIG_DIR"
  cat > "$PROXY_ENV_FILE" <<EOF
# 由 deploy_911vulscan.sh 生成
export HTTP_PROXY="${PROXY_URL}"
export HTTPS_PROXY="${PROXY_URL}"
export ALL_PROXY="${PROXY_URL}"
export http_proxy="${PROXY_URL}"
export https_proxy="${PROXY_URL}"
export all_proxy="${PROXY_URL}"
EOF
  info "Shell 代理: ${PROXY_ENV_FILE}"
}

configure_docker_proxy() {
  log "Step 4/8: 配置 Docker 代理"

  need_sudo
  local daemon_json="/etc/docker/daemon.json"
  sudo mkdir -p /etc/docker

  if [[ -f "$daemon_json" ]] && command -v python3 >/dev/null 2>&1; then
    sudo python3 - "$daemon_json" "$PROXY_URL" "$DEFAULT_NO_PROXY" <<'PY'
import json, sys
path, proxy, no_proxy = sys.argv[1:4]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except (json.JSONDecodeError, OSError):
    data = {}
data["proxies"] = {"http-proxy": proxy, "https-proxy": proxy, "no-proxy": no_proxy}
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
  else
    sudo tee "$daemon_json" > /dev/null <<EOF
{
  "proxies": {
    "http-proxy": "${PROXY_URL}",
    "https-proxy": "${PROXY_URL}",
    "no-proxy": "${DEFAULT_NO_PROXY}"
  }
}
EOF
  fi

  mkdir -p "${HOME}/.docker"
  cat > "${HOME}/.docker/config.json" <<EOF
{
  "proxies": {
    "default": {
      "httpProxy": "${PROXY_URL}",
      "httpsProxy": "${PROXY_URL}",
      "noProxy": "${DEFAULT_NO_PROXY}"
    }
  }
}
EOF

  sudo systemctl daemon-reload 2>/dev/null || true
  sudo systemctl restart docker 2>/dev/null || true
  info "Docker daemon + CLI 代理已配置"
}

# ---------------------------------------------------------------------------
# Step 6: LLM API（环境变量或交互式静默输入；密钥不进仓库/历史）
# ---------------------------------------------------------------------------
_read_secret() {
  # Silent prompt; does not echo and is not written to shell history.
  local prompt="$1"
  local value=""
  if [[ -r /dev/tty ]]; then
    # shellcheck disable=SC2162
    read -r -s -p "${prompt}" value </dev/tty || true
    echo >/dev/tty
  else
    # shellcheck disable=SC2162
    read -r -s -p "${prompt}" value || true
    echo
  fi
  printf '%s' "${value}"
}

_prompt_line() {
  local prompt="$1"
  local value=""
  if [[ -r /dev/tty ]]; then
    # shellcheck disable=SC2162
    read -r -p "${prompt}" value </dev/tty || true
  else
    # shellcheck disable=SC2162
    read -r -p "${prompt}" value || true
  fi
  printf '%s' "${value}"
}

configure_llm() {
  log "Step 6/8: 配置 LLM API（凭据仅来自环境变量或静默输入）"

  # Prefer already-exported credentials (CI / operator env). Never print values.
  if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
    _LLM_API_KEY="${DEEPSEEK_API_KEY}"
    VULSCAN_LLM_PROVIDER="${VULSCAN_LLM_PROVIDER:-deepseek}"
  elif [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    _LLM_API_KEY="${ANTHROPIC_API_KEY}"
    VULSCAN_LLM_PROVIDER="${VULSCAN_LLM_PROVIDER:-anthropic}"
  elif [[ -n "${VULSCAN_LLM_API_KEY:-}" ]]; then
    _LLM_API_KEY="${VULSCAN_LLM_API_KEY}"
  elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
    _LLM_API_KEY="${OPENAI_API_KEY}"
  elif [[ -n "${DASHSCOPE_API_KEY:-}" ]]; then
    _LLM_API_KEY="${DASHSCOPE_API_KEY}"
    VULSCAN_LLM_PROVIDER="${VULSCAN_LLM_PROVIDER:-qwen}"
  fi

  if [[ -z "${VULSCAN_LLM_PROVIDER}" ]]; then
    VULSCAN_LLM_PROVIDER="$(_prompt_line "LLM provider [anthropic|deepseek|qwen|openai_compat]: ")"
  fi
  VULSCAN_LLM_PROVIDER="$(echo "${VULSCAN_LLM_PROVIDER}" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "${VULSCAN_LLM_PROVIDER}" in
    anthropic|deepseek|qwen|openai_compat) ;;
    *) die "Unsupported VULSCAN_LLM_PROVIDER=${VULSCAN_LLM_PROVIDER:-<empty>}" ;;
  esac

  if [[ -z "${VULSCAN_LLM_MODEL}" ]]; then
    VULSCAN_LLM_MODEL="$(_prompt_line "LLM model id (required): ")"
  fi
  VULSCAN_LLM_MODEL="$(echo "${VULSCAN_LLM_MODEL}" | xargs)"
  [[ -n "${VULSCAN_LLM_MODEL}" ]] || die "VULSCAN_LLM_MODEL is required"

  if [[ "${VULSCAN_LLM_PROVIDER}" == "openai_compat" && -z "${VULSCAN_LLM_BASE_URL}" ]]; then
    VULSCAN_LLM_BASE_URL="$(_prompt_line "VULSCAN_LLM_BASE_URL (required for openai_compat): ")"
    VULSCAN_LLM_BASE_URL="$(echo "${VULSCAN_LLM_BASE_URL}" | xargs)"
    [[ -n "${VULSCAN_LLM_BASE_URL}" ]] || die "VULSCAN_LLM_BASE_URL is required for openai_compat"
  fi

  if [[ -z "${_LLM_API_KEY}" ]]; then
    _LLM_API_KEY="$(_read_secret "API key (input hidden, not saved to history): ")"
  fi
  [[ -n "${_LLM_API_KEY}" ]] || die "API key is required (set env or enter interactively)"

  mkdir -p "$CONFIG_DIR"
  umask 077
  # Provider/model only in llm.env. The API key is stored solely via
  # `vulscan set-api-key --stdin` into ~/.config/vulscan/config.json (0600).
  # Never write keys into the git repo or pass them as argv.
  {
    echo "# Generated by deploy_911vulscan.sh — mode 0600; do not commit"
    echo "# API keys are NOT stored here — see ~/.config/vulscan/config.json"
    echo "export VULSCAN_LLM_PROVIDER=\"${VULSCAN_LLM_PROVIDER}\""
    echo "export VULSCAN_LLM_MODEL=\"${VULSCAN_LLM_MODEL}\""
    if [[ -n "${VULSCAN_LLM_BASE_URL}" ]]; then
      echo "export VULSCAN_LLM_BASE_URL=\"${VULSCAN_LLM_BASE_URL}\""
    fi
  } >"$LLM_ENV_FILE"
  chmod 600 "$LLM_ENV_FILE"
  info "LLM 环境文件已写入（0600，无密钥）: ${LLM_ENV_FILE}"

  # shellcheck disable=SC1090
  source "$LLM_ENV_FILE"
  # Pass key via stdin — never as argv (avoids process list / shell history).
  printf '%s\n' "${_LLM_API_KEY}" | "$VULSCAN_BIN" set-api-key --stdin
  info "vulscan set-api-key 已完成（stdin → 0600 config）"

  # Drop in-memory copy from this shell as soon as possible.
  _LLM_API_KEY=""
  unset _LLM_API_KEY
}

# ---------------------------------------------------------------------------
# Step 5: Python venv + JS npm 预装
# ---------------------------------------------------------------------------
bootstrap_python_venv() {
  log "Step 5/8: 预装 Python 环境 (vulscan-core)"

  local venv_dir="${HOME}/.vulscan/venv"
  local core_path="${VULSCAN_ROOT}/libs/vulscan-core"

  if [[ ! -d "$core_path" ]]; then
    die "未找到 vulscan-core: ${core_path}"
  fi

  if [[ ! -x "${venv_dir}/bin/python" ]]; then
    "$PYTHON_BIN" -m venv "$venv_dir"
  fi

  # shellcheck disable=SC1091
  source "${PROXY_ENV_FILE}"
  "${venv_dir}/bin/pip" install --upgrade pip setuptools wheel -q
  "${venv_dir}/bin/pip" install -e "${core_path}" -q
  "${venv_dir}/bin/python" -c "import vulscan; print('import vulscan OK')"
  info "Python venv: ${venv_dir}"
}

bootstrap_js_parser() {
  local js_dir="${VULSCAN_ROOT}/libs/vulscan-core/parsers/javascript"
  export PATH="${NODE_DIR}/bin:${PATH}"

  if [[ -f "${js_dir}/node_modules/.package-lock.json" ]]; then
    info "JS 解析器依赖已安装"
    return 0
  fi

  echo "安装 JS 解析器 npm 依赖（首次约 1 分钟）..."
  # shellcheck disable=SC1091
  source "${PROXY_ENV_FILE}"
  cd "$js_dir"
  npm install --silent
  info "JS 解析器 npm 依赖已安装"
}

# ---------------------------------------------------------------------------
# Step 7: 写入全局环境（新终端自动生效）
# ---------------------------------------------------------------------------
write_global_env() {
  log "Step 7/8: 写入全局环境配置（新终端自动生效）"

  mkdir -p "$CONFIG_DIR"
  {
    cat <<EOF
# 由 deploy_911vulscan.sh 生成 — 新终端自动加载
# 生成时间: $(date -Iseconds)
# 源码目录: ${VULSCAN_ROOT}

export VULSCAN_ROOT="${VULSCAN_ROOT}"
export VULSCAN_BIN="${VULSCAN_BIN}"
export PYTHON_BIN="${PYTHON_BIN}"
export PYTHON_SOURCE="${PYTHON_SOURCE}"
export PATH="${NODE_DIR}/bin:/usr/local/go/bin:/usr/local/bin:${CLI_DIR}/bin:\${PATH}"
EOF
    if [[ "${PYTHON_SOURCE}" == "conda" && -n "${CONDA_ROOT}" && -n "${CONDA_ENV_DIR}" ]]; then
      cat <<EOF

# Python 3.11（Conda 默认环境）
export CONDA_ROOT="${CONDA_ROOT}"
export VULSCAN_PYTHON_ENV="${CONDA_ENV_NAME}"
export CONDA_DEFAULT_ENV="${CONDA_ENV_NAME}"
export CONDA_PREFIX="${CONDA_ENV_DIR}"
export PATH="${CONDA_ENV_DIR}/bin:${CONDA_ROOT}/bin:\${PATH}"
if [[ -f "${CONDA_ROOT}/etc/profile.d/conda.sh" ]]; then
  # shellcheck disable=SC1091
  source "${CONDA_ROOT}/etc/profile.d/conda.sh"
  conda activate "${CONDA_ENV_NAME}" 2>/dev/null || true
fi
EOF
    fi
    cat <<EOF

# 代理
[[ -f "${PROXY_ENV_FILE}" ]] && source "${PROXY_ENV_FILE}"

# LLM credentials (0600 user file — never commit)
[[ -f "${LLM_ENV_FILE}" ]] && source "${LLM_ENV_FILE}"
EOF
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  info "环境文件: ${ENV_FILE}"

  install_shell_hook "${HOME}/.bashrc"
  if [[ -f "${HOME}/.profile" ]]; then
    install_shell_hook "${HOME}/.profile"
  fi
  if [[ -f "${HOME}/.zshrc" ]]; then
    install_shell_hook "${HOME}/.zshrc"
  fi
}

install_shell_hook() {
  local rcfile="$1"
  [[ -f "$rcfile" ]] || touch "$rcfile"

  if grep -qF "$BASHRC_MARKER_BEGIN" "$rcfile" 2>/dev/null; then
    # 更新已有块
    local tmp="${rcfile}.911vulscan.tmp"
    awk -v begin="$BASHRC_MARKER_BEGIN" -v end="$BASHRC_MARKER_END" -v env="$ENV_FILE" '
      $0 == begin { skip=1; print begin; print "[[ -f \"" env "\" ]] && source \"" env "\""; next }
      $0 == end { skip=0; print end; next }
      !skip { print }
    ' "$rcfile" > "$tmp" && mv "$tmp" "$rcfile"
  else
    cat >> "$rcfile" <<EOF

${BASHRC_MARKER_BEGIN}
[[ -f "${ENV_FILE}" ]] && source "${ENV_FILE}"
${BASHRC_MARKER_END}
EOF
  fi
  info "已写入: ${rcfile}"
}

# ---------------------------------------------------------------------------
# Step 8: 验证
# ---------------------------------------------------------------------------
verify_deployment() {
  log "Step 8/8: 部署验证"

  local pass=0 fail=0

  check() {
    if eval "$2" >/dev/null 2>&1; then
      info "$1"
      pass=$((pass + 1))
    else
      echo "  ✗ $1"
      fail=$((fail + 1))
    fi
  }

  export PATH="${NODE_DIR}/bin:/usr/local/go/bin:/usr/local/bin:${CLI_DIR}/bin:${PATH}"
  # shellcheck disable=SC1091
  source "${ENV_FILE}"

  check "python3.11" "python311_ready python3.11 || python311_ready \"${PYTHON_BIN}\""
  if [[ "${PYTHON_SOURCE}" == "conda" ]]; then
    check "conda py3.11 默认环境" "test \"\${CONDA_DEFAULT_ENV:-}\" = \"${CONDA_ENV_NAME}\" || test -x \"${CONDA_ENV_DIR}/bin/python3.11\""
  fi
  check "go" "command -v go"
  check "docker" "command -v docker"
  check "node >= 18" "node --version | grep -qE '^v(1[89]|[2-9][0-9])'"
  check "vulscan CLI" "test -x ${VULSCAN_BIN}"
  check "vulscan 在 PATH" "command -v vulscan"
  check "import vulscan" "${HOME}/.vulscan/venv/bin/python -c 'import vulscan'"
  check "LLM 配置" "test -f ${LLM_ENV_FILE}"
  check "代理配置" "test -f ${PROXY_ENV_FILE}"
  check "全局 env.sh" "test -f ${ENV_FILE}"

  echo
  echo "验证结果: ${pass} 通过, ${fail} 失败"
  [[ "$fail" -eq 0 ]] || warn "部分检查未通过，见上方详情"
}

print_finish_message() {
  echo
  log "部署完成 — 开箱即用"
  cat <<EOF

新开终端后可直接使用，无需再 source 任何脚本。

快速开始:
  vulscan init <源码路径> -l c --name local/myproj
  vulscan scan --scope reachable --workers 8

常用命令:
  vulscan init <路径> -l javascript --name local/lodash   # JS 项目
  vulscan dynamic-test                                     # 动态测试（需 Docker）

当前配置:
  源码:   ${VULSCAN_ROOT}
  Python: ${PYTHON_BIN} (${PYTHON_SOURCE:-unknown})
  代理:   ${PROXY_URL}
  模型:   ${VULSCAN_LLM_PROVIDER:-unset} / ${VULSCAN_LLM_MODEL:-unset}
  环境:   ${ENV_FILE}
  密钥:   仅保存在 ~/.config/vulscan/config.json (0600)

若 docker ps 报权限错误:
  newgrp docker
  或重新登录后再试

EOF
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  echo "911VulScan 一键部署"
  echo "脚本位置: ${SCRIPT_DIR}"

  resolve_vulscan_root
  read_proxy_from_user
  write_proxy_env

  install_system_deps
  install_node
  build_vulscan
  configure_docker_proxy
  bootstrap_python_venv
  bootstrap_js_parser
  configure_llm
  write_global_env
  verify_deployment
  print_finish_message

  # 让当前 shell 也立刻可用（若用户在同一终端继续操作）
  # shellcheck disable=SC1091
  source "${ENV_FILE}"
}

main "$@"
