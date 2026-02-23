#!/usr/bin/env python3
"""Performance benchmarking and graphing script for pykyber.

This script runs the performance tests from python/tests/test_kyber.py
and generates graphs from the results.
"""

import subprocess
import re
import matplotlib.pyplot as plt


def run_performance_tests():
    """Run pytest performance tests and parse results."""
    result = subprocess.run(
        ['.venv/bin/python', '-m', 'pytest', 
         'python/tests/test_kyber.py', 
         '-v', '-k', 'performance', 
         '--tb=no', '-q', '-s'],
        capture_output=True,
        text=True
    )
    
    output = result.stdout + result.stderr
    
    results = {
        'Kyber512': {},
        'Kyber768': {},
        'Kyber1024': {}
    }
    
    pattern = r'Kyber(\d+)\s+(keypair generation|encapsulation|decapsulation|full key exchange.*?):\s+([\d.]+)\s+ms/op'
    
    for match in re.finditer(pattern, output):
        variant = f"Kyber{match.group(1)}"
        operation = match.group(2).strip()
        time_ms = float(match.group(3))
        
        if 'keypair generation' in operation:
            results[variant]['keypair'] = time_ms
        elif 'encapsulation' in operation:
            results[variant]['encapsulate'] = time_ms
        elif 'decapsulation' in operation:
            results[variant]['decapsulate'] = time_ms
        elif 'class API' in operation:
            results[variant]['class_api'] = time_ms
        elif 'static methods' in operation:
            results[variant]['static_methods'] = time_ms
    
    return results


def create_comparison_chart(results):
    """Create a comparison chart across all variants and operations."""
    variants = ['Kyber512', 'Kyber768', 'Kyber1024']
    
    x = range(len(variants))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    keypair_times = [results[v]['keypair'] for v in variants]
    encapsulate_times = [results[v]['encapsulate'] for v in variants]
    decapsulate_times = [results[v]['decapsulate'] for v in variants]
    
    bars1 = ax.bar([i - width for i in x], keypair_times, width, label='Keypair Generation', color='#2ecc71')
    bars2 = ax.bar(x, encapsulate_times, width, label='Encapsulation', color='#3498db')
    bars3 = ax.bar([i + width for i in x], decapsulate_times, width, label='Decapsulation', color='#e74c3c')
    
    ax.set_xlabel('Kyber Variant', fontsize=12)
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_title('PyKyber Performance Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(variants)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.2f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig('performance-tests/performance_comparison.png', dpi=150)
    print("Saved: performance-tests/performance_comparison.png")
    plt.close()


def create_operation_breakdown(results):
    """Create individual charts for each operation."""
    variants = ['Kyber512', 'Kyber768', 'Kyber1024']
    colors = ['#2ecc71', '#3498db', '#e74c3c']
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    operations = ['keypair', 'encapsulate', 'decapsulate']
    titles = ['Keypair Generation', 'Encapsulation', 'Decapsulation']
    
    for idx, (op, title) in enumerate(zip(operations, titles)):
        times = [results[v][op] for v in variants]
        bars = axes[idx].bar(variants, times, color=colors)
        axes[idx].set_title(title, fontsize=12, fontweight='bold')
        axes[idx].set_ylabel('Time (ms)')
        axes[idx].grid(axis='y', alpha=0.3)
        
        for bar in bars:
            height = bar.get_height()
            axes[idx].annotate(f'{height:.2f}',
                             xy=(bar.get_x() + bar.get_width() / 2, height),
                             xytext=(0, 3),
                             textcoords="offset points",
                             ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('performance-tests/operation_breakdown.png', dpi=150)
    print("Saved: performance-tests/operation_breakdown.png")
    plt.close()


def create_scalability_chart(results):
    """Create a chart showing how performance scales with security level."""
    variants = ['Kyber512', 'Kyber768', 'Kyber1024']
    security_levels = ['~AES-128', '~AES-192', '~AES-256']
    
    keypair_times = [results[v]['keypair'] for v in variants]
    encapsulate_times = [results[v]['encapsulate'] for v in variants]
    decapsulate_times = [results[v]['decapsulate'] for v in variants]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = range(len(variants))
    
    ax.plot(x, keypair_times, 'o-', linewidth=2, markersize=8, label='Keypair Generation', color='#2ecc71')
    ax.plot(x, encapsulate_times, 's-', linewidth=2, markersize=8, label='Encapsulation', color='#3498db')
    ax.plot(x, decapsulate_times, '^-', linewidth=2, markersize=8, label='Decapsulation', color='#e74c3c')
    
    ax.set_xticks(x)
    ax.set_xticklabels([f'{v}\n({s})' for v, s in zip(variants, security_levels)])
    ax.set_xlabel('Kyber Variant (Security Level)', fontsize=12)
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.set_title('PyKyber Performance Scalability', fontsize=14, fontweight='bold')
    ax.legend()
    ax.grid(alpha=0.3)
    
    for i, variant in enumerate(variants):
        for j, (data, label) in enumerate([(keypair_times, 'keypair'), 
                                            (encapsulate_times, 'encapsulate'), 
                                            (decapsulate_times, 'decapsulate')]):
            ax.annotate(f'{data[i]:.2f}', 
                       (i, data[i]), 
                       textcoords="offset points", 
                       xytext=(0, 10), 
                       ha='center', fontsize=8)
    
    plt.tight_layout()
    plt.savefig('performance-tests/scalability.png', dpi=150)
    print("Saved: performance-tests/scalability.png")
    plt.close()


def create_throughput_chart(results):
    """Create a throughput chart showing operations per second."""
    variants = ['Kyber512', 'Kyber768', 'Kyber1024']
    
    keypair_ops = [1000 / results[v]['keypair'] for v in variants]
    encapsulate_ops = [1000 / results[v]['encapsulate'] for v in variants]
    decapsulate_ops = [1000 / results[v]['decapsulate'] for v in variants]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = range(len(variants))
    width = 0.25
    
    bars1 = ax.bar([i - width for i in x], keypair_ops, width, label='Keypair Generation', color='#2ecc71')
    bars2 = ax.bar(x, encapsulate_ops, width, label='Encapsulation', color='#3498db')
    bars3 = ax.bar([i + width for i in x], decapsulate_ops, width, label='Decapsulation', color='#e74c3c')
    
    ax.set_xlabel('Kyber Variant', fontsize=12)
    ax.set_ylabel('Operations per Second', fontsize=12)
    ax.set_title('PyKyber Throughput (Operations per Second)', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(variants)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{int(height)}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig('performance-tests/throughput.png', dpi=150)
    print("Saved: performance-tests/throughput.png")
    plt.close()


def print_summary(results):
    """Print a summary table of results."""
    print("\n" + "=" * 60)
    print("PyKyber Performance Summary (100 iterations each)")
    print("=" * 60)
    print(f"{'Variant':<12} {'Keypair (ms)':<15} {'Encapsulate (ms)':<18} {'Decapsulate (ms)':<18}")
    print("-" * 60)
    for variant in ['Kyber512', 'Kyber768', 'Kyber1024']:
        r = results[variant]
        print(f"{variant:<12} {r['keypair']:<15.3f} {r['encapsulate']:<18.3f} {r['decapsulate']:<18.3f}")
    print("=" * 60)
    
    print("\nThroughput (operations/second):")
    print("-" * 60)
    print(f"{'Variant':<12} {'Keypair/s':<15} {'Encapsulate/s':<18} {'Decapsulate/s':<18}")
    print("-" * 60)
    for variant in ['Kyber512', 'Kyber768', 'Kyber1024']:
        r = results[variant]
        kp_ops = int(1000 / r['keypair'])
        enc_ops = int(1000 / r['encapsulate'])
        dec_ops = int(1000 / r['decapsulate'])
        print(f"{variant:<12} {kp_ops:<15} {enc_ops:<18} {dec_ops:<18}")
    print("=" * 60)


if __name__ == '__main__':
    print("Running performance tests from python/tests/test_kyber.py...")
    results = run_performance_tests()
    print_summary(results)
    create_comparison_chart(results)
    create_operation_breakdown(results)
    create_scalability_chart(results)
    create_throughput_chart(results)
    print("\nAll graphs saved in performance-tests/")
