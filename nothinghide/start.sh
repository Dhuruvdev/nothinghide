#!/bin/bash
#
# NothingHide CLI Startup Script
# ==============================
# This script handles all initialization, dependency checking,
# and proper CLI startup with loading animations.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'

SPINNER_CHARS="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_DELAY=0.1

show_spinner() {
    local pid=$1
    local message=$2
    local i=0
    local len=${#SPINNER_CHARS}
    
    while kill -0 $pid 2>/dev/null; do
        local char="${SPINNER_CHARS:$((i % len)):1}"
        printf "\r  ${CYAN}%s${NC} %s" "$char" "$message"
        sleep $SPINNER_DELAY
        ((i++))
    done
    
    wait $pid
    return $?
}

show_success() {
    printf "\r  ${GREEN}✓${NC} %s\n" "$1"
}

show_error() {
    printf "\r  ${RED}✗${NC} %s\n" "$1"
}

show_warning() {
    printf "\r  ${YELLOW}⚠${NC} %s\n" "$1"
}

show_info() {
    printf "  ${CYAN}●${NC} %s\n" "$1"
}

show_header() {
    echo ""
    echo -e "  ${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${CYAN}║${NC}           ${WHITE}NOTHINGHIDE CLI - Startup Script${NC}             ${CYAN}║${NC}"
    echo -e "  ${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        show_error "Python not found"
        echo -e "  ${YELLOW}Please install Python 3.10 or higher${NC}"
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]); then
        show_error "Python 3.10+ required (found $PYTHON_VERSION)"
        exit 1
    fi
    
    show_success "Python $PYTHON_VERSION detected"
}

check_virtual_env() {
    if [ -n "$VIRTUAL_ENV" ]; then
        show_success "Virtual environment active"
    else
        show_info "Running in system Python environment"
    fi
}

check_dependencies() {
    local missing_deps=()
    local all_deps=("typer" "rich" "httpx" "email_validator" "halo" "yaspin" "colorama")
    
    for dep in "${all_deps[@]}"; do
        if ! $PYTHON_CMD -c "import $dep" 2>/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        show_success "All dependencies installed"
        return 0
    else
        show_warning "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
}

install_dependencies() {
    echo -e "  ${CYAN}●${NC} Installing dependencies..."
    
    if [ -f "$PROJECT_ROOT/pyproject.toml" ]; then
        cd "$PROJECT_ROOT"
        if command -v uv &> /dev/null; then
            uv sync --quiet 2>/dev/null || pip install -e . --quiet
        else
            pip install -e . --quiet 2>/dev/null || pip install -r requirements.txt --quiet 2>/dev/null
        fi
    fi
    
    show_success "Dependencies installed"
}

verify_app_structure() {
    local required_files=(
        "app/__init__.py"
        "app/main.py"
        "app/branding.py"
        "app/config.py"
        "app/utils.py"
        "app/email_check.py"
        "app/password_check.py"
    )
    
    local missing_files=()
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$PROJECT_ROOT/$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -eq 0 ]; then
        show_success "Application structure verified"
        return 0
    else
        show_error "Missing files: ${missing_files[*]}"
        return 1
    fi
}

load_environment() {
    if [ -f "$PROJECT_ROOT/.env" ]; then
        set -a
        source "$PROJECT_ROOT/.env"
        set +a
        show_success "Environment loaded from .env"
    else
        show_info "No .env file found (using defaults)"
    fi
}

check_network() {
    if curl -s --head --max-time 3 "https://api.pwnedpasswords.com/range/00000" > /dev/null 2>&1; then
        show_success "Network connectivity verified"
        return 0
    else
        show_warning "Network check failed (offline mode available)"
        return 0
    fi
}

cleanup() {
    find "$PROJECT_ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_ROOT" -type f -name "*.pyc" -delete 2>/dev/null || true
}

start_cli() {
    echo ""
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}✓ All checks passed! Starting NothingHide CLI...${NC}"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    sleep 0.5
    
    cd "$PROJECT_ROOT"
    exec $PYTHON_CMD -m app.main "$@"
}

show_help() {
    echo ""
    echo "NothingHide CLI Startup Script"
    echo ""
    echo "Usage: ./start.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h       Show this help message"
    echo "  --quick, -q      Quick start (skip detailed checks)"
    echo "  --check          Run checks only, don't start CLI"
    echo "  --install        Install/update dependencies"
    echo "  --clean          Clean up cache files"
    echo "  --skip-network   Skip network connectivity check"
    echo ""
}

main() {
    local QUICK_START=false
    local CHECK_ONLY=false
    local INSTALL_DEPS=false
    local CLEAN_CACHE=false
    local SKIP_NETWORK=false
    local CLI_ARGS=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --quick|-q)
                QUICK_START=true
                shift
                ;;
            --check)
                CHECK_ONLY=true
                shift
                ;;
            --install)
                INSTALL_DEPS=true
                shift
                ;;
            --clean)
                CLEAN_CACHE=true
                shift
                ;;
            --skip-network)
                SKIP_NETWORK=true
                shift
                ;;
            *)
                CLI_ARGS+=("$1")
                shift
                ;;
        esac
    done
    
    if [ "$CLEAN_CACHE" = true ]; then
        echo "Cleaning cache files..."
        cleanup
        show_success "Cache cleaned"
        exit 0
    fi
    
    show_header
    
    if [ "$QUICK_START" = true ]; then
        echo -e "  ${GRAY}Running quick startup...${NC}"
        echo ""
        check_python
        cd "$PROJECT_ROOT"
        exec $PYTHON_CMD -m app.main "${CLI_ARGS[@]}"
    fi
    
    check_python
    check_virtual_env
    
    if ! check_dependencies || [ "$INSTALL_DEPS" = true ]; then
        install_dependencies
    fi
    
    if ! verify_app_structure; then
        echo -e "\n  ${RED}Application files are missing. Cannot start.${NC}"
        exit 1
    fi
    
    load_environment
    
    if [ "$SKIP_NETWORK" = false ]; then
        check_network
    fi
    
    if [ "$CHECK_ONLY" = true ]; then
        echo ""
        echo -e "  ${GREEN}All checks completed successfully!${NC}"
        echo ""
        exit 0
    fi
    
    start_cli "${CLI_ARGS[@]}"
}

main "$@"
