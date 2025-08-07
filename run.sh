#!/bin/bash

# Fail2Shield Dashboard - Launcher Script
# This script sets up the environment and launches the Streamlit application

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="Fail2Shield Dashboard"
APP_PORT=8501
PYTHON_MIN_VERSION="3.8"
VENV_DIR="venv"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        print_error "Python is not installed or not in PATH"
        exit 1
    fi

    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        print_error "Python $PYTHON_MIN_VERSION or higher is required. Found: $PYTHON_VERSION"
        exit 1
    fi

    print_success "Python $PYTHON_VERSION detected"
}

# Function to check system requirements
check_system_requirements() {
    print_status "Checking system requirements..."

    # Check if fail2ban-client exists
    if ! command_exists fail2ban-client; then
        print_warning "fail2ban-client not found in PATH"
        print_warning "Make sure fail2ban is installed: sudo apt-get install fail2ban"
        print_warning "The application will still start but may have limited functionality"
    else
        print_success "fail2ban-client found"
    fi

    # Check if we can read fail2ban status (requires appropriate permissions)
    if command_exists fail2ban-client; then
        if fail2ban-client ping >/dev/null 2>&1; then
            print_success "fail2ban service is running and accessible"
        else
            print_warning "Cannot communicate with fail2ban service"
            print_warning "You may need to run this application with appropriate permissions"
            print_warning "Try: sudo ./run.sh"
        fi
    fi

    # Check log file access
    if [ -f "/var/log/fail2ban.log" ]; then
        if [ -r "/var/log/fail2ban.log" ]; then
            print_success "fail2ban log file is accessible"
        else
            print_warning "Cannot read fail2ban log file"
            print_warning "Log viewing functionality may be limited"
        fi
    else
        print_warning "fail2ban log file not found at /var/log/fail2ban.log"
    fi
}

# Function to setup virtual environment
setup_virtual_environment() {
    print_status "Setting up Python virtual environment..."

    if [ ! -d "$VENV_DIR" ]; then
        print_status "Creating virtual environment..."
        $PYTHON_CMD -m venv $VENV_DIR
        print_success "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi

    # Activate virtual environment
    source $VENV_DIR/bin/activate
    print_success "Virtual environment activated"

    # Upgrade pip
    print_status "Upgrading pip..."
    pip install --upgrade pip >/dev/null 2>&1
    print_success "pip upgraded"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."

    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt >/dev/null 2>&1
        print_success "Dependencies installed successfully"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Function to check application files
check_application_files() {
    print_status "Checking application files..."

    required_files=("app.py" "config.py" "utils.py" "fail2ban_manager.py")

    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "Required file missing: $file"
            exit 1
        fi
    done

    print_success "All required files present"
}

# Function to start the application
start_application() {
    print_status "Starting $APP_NAME..."
    print_status "The application will be available at: http://localhost:$APP_PORT"
    print_status "Press Ctrl+C to stop the application"
    echo ""

    # Start Streamlit
    streamlit run app.py --server.port $APP_PORT --server.headless true --browser.gatherUsageStats false
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."
    if [ -d "$VENV_DIR" ] && [ "$CLEANUP_VENV" = "true" ]; then
        rm -rf $VENV_DIR
        print_status "Virtual environment removed"
    fi
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --clean             Clean virtual environment before setup"
    echo "  --no-venv           Skip virtual environment setup"
    echo "  --port PORT         Specify port number (default: $APP_PORT)"
    echo "  --check-only        Only check requirements, don't start app"
    echo ""
    echo "Examples:"
    echo "  $0                  Start the application normally"
    echo "  $0 --clean          Clean setup and start"
    echo "  $0 --port 8080      Start on port 8080"
    echo "  sudo $0             Start with elevated privileges"
    echo ""
}

# Parse command line arguments
USE_VENV=true
CLEAN_SETUP=false
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --clean)
            CLEAN_SETUP=true
            shift
            ;;
        --no-venv)
            USE_VENV=false
            shift
            ;;
        --port)
            APP_PORT="$2"
            shift 2
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo ""
    echo "🛡️  $APP_NAME Launcher"
    echo "=================================="
    echo ""

    # Trap cleanup on exit
    trap cleanup EXIT

    # Clean setup if requested
    if [ "$CLEAN_SETUP" = "true" ] && [ -d "$VENV_DIR" ]; then
        print_status "Cleaning previous setup..."
        rm -rf $VENV_DIR
        print_success "Previous setup cleaned"
    fi

    # Check requirements
    check_python_version
    check_system_requirements
    check_application_files

    if [ "$CHECK_ONLY" = "true" ]; then
        print_success "All checks passed!"
        exit 0
    fi

    # Setup environment
    if [ "$USE_VENV" = "true" ]; then
        setup_virtual_environment
        install_dependencies
    else
        print_warning "Skipping virtual environment setup"
        print_status "Installing dependencies globally..."
        pip install -r requirements.txt >/dev/null 2>&1
    fi

    # Start application
    start_application
}

# Run main function
main "$@"