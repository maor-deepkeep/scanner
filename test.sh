#!/bin/bash

# ModelTotal Test Runner - Run tests safely inside Docker containers
# All scanners and ML frameworks stay isolated in Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
DOCKER_IMAGE="modeltotal-model-total:latest"
NETWORK="backend_network"
RESULTS_DIR="test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function to print usage
usage() {
    echo -e "${BOLD}ModelTotal Test Runner${NC}"
    echo -e "${CYAN}Run tests safely inside Docker containers${NC}"
    echo ""
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  ./test.sh [command] [options]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}all${NC}              Run all unit tests"
    echo -e "  ${GREEN}scanner${NC} <name>   Run specific scanner tests (picklescan, modelscan, fickling, etc.)"
    echo -e "  ${GREEN}file${NC} <path>      Run specific test file"
    echo -e "  ${GREEN}integration${NC}      Run integration tests"
    echo -e "  ${GREEN}quick${NC}            Run quick smoke tests"
    echo -e "  ${GREEN}coverage${NC}         Run tests with coverage report"
    echo -e "  ${GREEN}debug${NC} <test>     Run specific test with debugging output"
    echo -e "  ${GREEN}shell${NC}            Open interactive shell in test container"
    echo -e "  ${GREEN}clean${NC}            Clean test results"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ./test.sh all                                    # Run all tests"
    echo -e "  ./test.sh scanner picklescan                     # Run picklescan tests"
    echo -e "  ./test.sh file tests/unit/test_validator.py      # Run specific file"
    echo -e "  ./test.sh debug test_scan_malicious_pickle_files # Debug specific test"
    echo -e "  ./test.sh coverage                               # Generate coverage report"
    echo ""
}

# Function to check Docker services
check_services() {
    echo -e "${YELLOW}Checking Docker services...${NC}"
    
    if ! docker-compose ps | grep -q "Up"; then
        echo -e "${YELLOW}Docker services are not running. Starting services...${NC}"
        
        # Clean up existing services and networks first
        echo -e "${CYAN}Cleaning up existing Docker resources...${NC}"
        docker-compose down --volumes --remove-orphans 2>/dev/null || true
        
        # Remove the problematic network if it exists
        docker network rm backend_network 2>/dev/null || true
        
        # Start services fresh
        docker-compose up -d --build
        sleep 10
        
        # Verify services are running
        if ! docker-compose ps | grep -q "Up"; then
            echo -e "${RED}Failed to start Docker services${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✓ Docker services are running${NC}"
}

# Function to create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    echo -e "${CYAN}Test results will be saved to: ${RESULTS_DIR}/${NC}"
}

# Function to run tests in Docker
run_in_docker() {
    local cmd="$1"
    local output_file="${RESULTS_DIR}/test_${TIMESTAMP}.log"
    
    echo -e "${BLUE}Running: ${cmd}${NC}"
    echo -e "${CYAN}Output: ${output_file}${NC}"
    echo ""
    
    # Run the Docker command and capture output
    docker run --rm \
        --network "$NETWORK" \
        -v "$(pwd)/tests:/app/tests:ro" \
        -v "$(pwd)/src:/app/src:ro" \
        -v "$(pwd)/${RESULTS_DIR}:/app/${RESULTS_DIR}" \
        -e PYTHONPATH=/app \
        -e PYTEST_CURRENT_TEST="" \
        -e MINIO_URL=http://minio:9000 \
        -e MINIO_ACCESS_KEY=minioadmin \
        -e MINIO_SECRET_KEY=minioadmin \
        -e MONGODB_URL=mongodb://admin:password123@mongodb:27017 \
        -e REDIS_URL=redis://redis:6379 \
        -w /app \
        "$DOCKER_IMAGE" \
        bash -c "$cmd" 2>&1 | tee "$output_file"
    
    return ${PIPESTATUS[0]}
}

# Function to generate test summary
generate_summary() {
    local log_file="$1"
    local summary_file="${RESULTS_DIR}/summary_${TIMESTAMP}.txt"
    
    echo -e "\n${BOLD}Test Summary:${NC}" | tee "$summary_file"
    echo "═══════════════════════════════════════" | tee -a "$summary_file"
    
    # Extract test results
    if grep -q "passed" "$log_file"; then
        local passed=$(grep -oE "[0-9]+ passed" "$log_file" | tail -1)
        local failed=$(grep -oE "[0-9]+ failed" "$log_file" | tail -1)
        local skipped=$(grep -oE "[0-9]+ skipped" "$log_file" | tail -1)
        
        echo -e "${GREEN}✓ Passed: ${passed:-0}${NC}" | tee -a "$summary_file"
        if [ -n "$failed" ]; then
            echo -e "${RED}✗ Failed: ${failed}${NC}" | tee -a "$summary_file"
        fi
        if [ -n "$skipped" ]; then
            echo -e "${YELLOW}⊘ Skipped: ${skipped}${NC}" | tee -a "$summary_file"
        fi
        
        # Show failed test names
        if [ -n "$failed" ]; then
            echo -e "\n${BOLD}Failed Tests:${NC}" | tee -a "$summary_file"
            grep "FAILED" "$log_file" | sed 's/FAILED /  • /' | tee -a "$summary_file"
        fi
    else
        echo -e "${RED}No test results found${NC}" | tee -a "$summary_file"
    fi
    
    echo "═══════════════════════════════════════" | tee -a "$summary_file"
    echo -e "\n${CYAN}Full log: ${log_file}${NC}"
    echo -e "${CYAN}Summary: ${summary_file}${NC}"
}

# Main script logic
main() {
    case "${1:-help}" in
        all)
            check_services
            setup_results_dir
            echo -e "${BOLD}Running all unit tests...${NC}\n"
            run_in_docker "python -m pytest tests/unit/ -v --tb=short"
            generate_summary "${RESULTS_DIR}/test_${TIMESTAMP}.log"
            ;;
            
        scanner)
            if [ -z "$2" ]; then
                echo -e "${RED}Error: Scanner name required${NC}"
                echo "Available scanners: picklescan, modelscan, fickling, trivy, validator, model_audit, pypi_license"
                exit 1
            fi
            check_services
            setup_results_dir
            echo -e "${BOLD}Running ${2} scanner tests...${NC}\n"
            run_in_docker "python -m pytest tests/unit/test_${2}_scanner.py -v --tb=short"
            generate_summary "${RESULTS_DIR}/test_${TIMESTAMP}.log"
            ;;
            
        file)
            if [ -z "$2" ]; then
                echo -e "${RED}Error: Test file path required${NC}"
                exit 1
            fi
            check_services
            setup_results_dir
            echo -e "${BOLD}Running test file: ${2}${NC}\n"
            run_in_docker "python -m pytest ${2} -v --tb=short"
            generate_summary "${RESULTS_DIR}/test_${TIMESTAMP}.log"
            ;;
            
        integration)
            check_services
            setup_results_dir
            echo -e "${BOLD}Running integration tests...${NC}\n"
            # Integration tests need to run on host to access Docker
            # Activate virtual environment if it exists
            if [ -d "venv" ]; then
                source venv/bin/activate
            fi
            output_file="${RESULTS_DIR}/test_${TIMESTAMP}.log"
            echo -e "${BLUE}Running: python -m pytest tests/integration/ -v --tb=short${NC}"
            echo -e "${CYAN}Output: ${output_file}${NC}"
            echo ""
            python -m pytest tests/integration/ -v --tb=short 2>&1 | tee "$output_file"
            generate_summary "$output_file"
            ;;
            
        quick)
            check_services
            setup_results_dir
            echo -e "${BOLD}Running quick smoke tests...${NC}\n"
            # Run one simple test from each scanner
            run_in_docker "python -m pytest \
                tests/unit/test_picklescan_scanner.py::TestPickleScanScanner::test_scan_empty_directory \
                tests/unit/test_modelscan_scanner.py::TestModelScanScanner::test_scan_empty_directory \
                tests/unit/test_fickling_scanner.py::TestFicklingScanner::test_scan_empty_pickle \
                -v --tb=short"
            generate_summary "${RESULTS_DIR}/test_${TIMESTAMP}.log"
            ;;
            
        coverage)
            check_services
            setup_results_dir
            echo -e "${BOLD}Running tests with coverage...${NC}\n"
            run_in_docker "python -m pytest tests/unit/ --cov=src.static_scan --cov-report=term --cov-report=html:${RESULTS_DIR}/coverage_${TIMESTAMP}"
            echo -e "\n${GREEN}Coverage report saved to: ${RESULTS_DIR}/coverage_${TIMESTAMP}/index.html${NC}"
            generate_summary "${RESULTS_DIR}/test_${TIMESTAMP}.log"
            ;;
            
        debug)
            if [ -z "$2" ]; then
                echo -e "${RED}Error: Test name or pattern required${NC}"
                exit 1
            fi
            check_services
            setup_results_dir
            echo -e "${BOLD}Running test in debug mode: ${2}${NC}\n"
            run_in_docker "python -m pytest tests/ -k '${2}' -vvs --tb=long --capture=no"
            ;;
            
        shell)
            check_services
            echo -e "${BOLD}Opening interactive shell in test container...${NC}"
            echo -e "${YELLOW}You can run pytest commands directly inside the container${NC}\n"
            docker run --rm -it \
                --network "$NETWORK" \
                -v "$(pwd)/tests:/app/tests:ro" \
                -v "$(pwd)/src:/app/src:ro" \
                -v "$(pwd)/${RESULTS_DIR}:/app/${RESULTS_DIR}" \
                -e PYTHONPATH=/app \
                -e MINIO_URL=http://minio:9000 \
                -e MINIO_ACCESS_KEY=minioadmin \
                -e MINIO_SECRET_KEY=minioadmin \
                -e MONGODB_URL=mongodb://admin:password123@mongodb:27017 \
                -e REDIS_URL=redis://redis:6379 \
                -w /app \
                "$DOCKER_IMAGE" \
                bash
            ;;
            
        clean)
            echo -e "${YELLOW}Cleaning test results...${NC}"
            if [ -d "$RESULTS_DIR" ]; then
                rm -rf "$RESULTS_DIR"
                echo -e "${GREEN}✓ Test results cleaned${NC}"
            else
                echo -e "${CYAN}No test results to clean${NC}"
            fi
            ;;
            
        help|--help|-h)
            usage
            ;;
            
        *)
            echo -e "${RED}Error: Unknown command '${1}'${NC}\n"
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"