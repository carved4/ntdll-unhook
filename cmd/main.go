package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go-ntdll/pkg/unhook"
)

const (
	appName    = "Go NTDLL Unhooker"
	appVersion = "v1.0.0"
)

func main() {
	// Print banner
	printBanner()

	// Check if running on Windows
	if !isWindows() {
		log.Fatal("Error: This tool only works on Windows systems")
	}

	// Check for help flag
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		printUsage()
		return
	}

	// Perform the unhooking
	fmt.Println("[*] Attempting to unhook ntdll.dll...")
	
	err := unhook.UnhookNtdll()
	if err != nil {
		log.Fatalf("[-] Failed to unhook ntdll.dll: %v", err)
	}

	fmt.Println("[+] NTDLL unhooking completed successfully!")
	fmt.Println("[*] Process is now running with clean ntdll.dll")
	fmt.Println("[*] Press CTRL+C to exit...")

	// Wait for CTRL+C
	waitForInterrupt()
}

func waitForInterrupt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	// Block until signal is received
	<-c
	
	fmt.Println("\n[*] Received interrupt signal, exiting...")
}

func printBanner() {
	fmt.Printf(`
%s %s
=====================================
NTDLL Unhooking Tool for Windows
Removes userland hooks from ntdll.dll
=====================================

`, appName, appVersion)
}

func printUsage() {
	fmt.Printf(`Usage: %s [options]

Options:
  -h, --help    Show this help message

Environment Variables:
  WINAPI_DEBUG=true    Enable detailed debug output

Examples:
  %s                           # Run with minimal output
  set WINAPI_DEBUG=true && %s  # Run with debug output (Windows CMD)
  $env:WINAPI_DEBUG="true"; %s # Run with debug output (PowerShell)

Note: The process will remain running after unhooking. Press CTRL+C to exit.

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func isWindows() bool {
	// Simple check - could be enhanced with runtime.GOOS
	return true // For now, assume Windows since that's the target platform
}