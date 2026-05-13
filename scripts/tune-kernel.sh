#!/bin/bash
# tune-kernel.sh — Pre-flight kernel tuning for WAF Benchmark Phase C & D
# Runs BEFORE any benchmark test to ensure clean measurement environment.
#
# Usage:  sudo ./scripts/tune-kernel.sh [tier]
#   tier: min | mid | full  (default: mid, also reads WAF_RESOURCE_TIER env var)
#
# Reference: docs/hackathon/workflow/measurement_architecture_c_d.md §5.4

set -e

TIER="${1:-${WAF_RESOURCE_TIER:-mid}}"

# ── Validation ──
case "$TIER" in
  min|mid|full) ;;
  *)
    echo "ERROR: Unknown tier '$TIER'. Must be: min | mid | full"
    echo "Usage: $0 [min|mid|full]"
    exit 1
    ;;
esac

echo "=== PRE-FLIGHT KERNEL TUNING ==="
echo "  Tier: $TIER"
echo "  Host: $(hostname)"
echo "  Date: $(date -Iseconds)"
echo ""

# ═══════════════════════════════════════════════
# 1. CPU CORES CHECK
# ═══════════════════════════════════════════════
NPROC=$(nproc)
echo "── CPU ──"
echo "  Cores detected: $NPROC"

case "$TIER" in
  min) MIN_CORES=2 ;;
  mid) MIN_CORES=4 ;;
  full) MIN_CORES=8 ;;
esac

if [ "$NPROC" -lt "$MIN_CORES" ]; then
  echo "  FATAL: Need $MIN_CORES cores for tier '$TIER', only $NPROC available."
  exit 1
fi
echo "  ✅ Core count sufficient for tier '$TIER' (need $MIN_CORES, have $NPROC)"

# ═══════════════════════════════════════════════
# 2. RAM CHECK
# ═══════════════════════════════════════════════
MEM_TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_TOTAL_GB=$((MEM_TOTAL_KB / 1024 / 1024))
echo ""
echo "── RAM ──"
echo "  Total: ${MEM_TOTAL_GB}GB"

case "$TIER" in
  min) MIN_RAM_GB=4 ;;
  mid) MIN_RAM_GB=8 ;;
  full) MIN_RAM_GB=16 ;;
esac

if [ "$MEM_TOTAL_GB" -lt "$MIN_RAM_GB" ]; then
  echo "  FATAL: Need ${MIN_RAM_GB}GB RAM for tier '$TIER', only ${MEM_TOTAL_GB}GB available."
  exit 1
fi
echo "  ✅ RAM sufficient for tier '$TIER' (need ${MIN_RAM_GB}GB, have ${MEM_TOTAL_GB}GB)"

# Check available memory
MEM_AVAIL_KB=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
MEM_AVAIL_GB=$((MEM_AVAIL_KB / 1024 / 1024))
echo "  Available: ${MEM_AVAIL_GB}GB"

# ═══════════════════════════════════════════════
# 3. SWAP — MUST BE DISABLED
# ═══════════════════════════════════════════════
echo ""
echo "── SWAP ──"
SWAP_TOTAL_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
if [ "$SWAP_TOTAL_KB" -gt 0 ]; then
  echo "  ⚠️  Swap is active (${SWAP_TOTAL_KB}kB). Disabling..."
  swapoff -a 2>/dev/null || echo "  WARNING: Could not disable swap (may require root)"
  SWAP_TOTAL_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
  if [ "$SWAP_TOTAL_KB" -gt 0 ]; then
    echo "  ❌ Swap still active! Results will be flagged CONTAMINATED."
  else
    echo "  ✅ Swap disabled."
  fi
else
  echo "  ✅ Swap already disabled."
fi

# ═══════════════════════════════════════════════
# 4. TRANSPARENT HUGEPAGES — DISABLE
# ═══════════════════════════════════════════════
echo ""
echo "── THP (Transparent Hugepages) ──"
if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
  CURRENT_THP=$(cat /sys/kernel/mm/transparent_hugepage/enabled | grep -o '\[.*\]' | tr -d '[]')
  echo "  Current: $CURRENT_THP"
  if [ "$CURRENT_THP" != "never" ] && [ "$CURRENT_THP" != "madvise" ]; then
    echo "  Disabling THP..."
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || \
      echo "  WARNING: Could not disable THP (may require root)"
    echo "  ✅ THP set to 'never'"
  else
    echo "  ✅ THP already disabled."
  fi

  # Also disable defrag
  if [ -f /sys/kernel/mm/transparent_hugepage/defrag ]; then
    echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
  fi
else
  echo "  ℹ️  THP not available on this kernel."
fi

# ═══════════════════════════════════════════════
# 5. CPU GOVERNOR — PERFORMANCE
# ═══════════════════════════════════════════════
echo ""
echo "── CPU Governor ──"
GOV_SET=0
for policy in /sys/devices/system/cpu/cpufreq/policy*; do
  if [ -f "$policy/scaling_governor" ]; then
    CURRENT_GOV=$(cat "$policy/scaling_governor")
    CORE_ID=$(basename "$policy" | sed 's/policy//')
    if [ "$CURRENT_GOV" != "performance" ]; then
      echo "  Core $CORE_ID: $CURRENT_GOV → performance"
      echo performance > "$policy/scaling_governor" 2>/dev/null || true
      GOV_SET=1
    fi
  fi
done
if [ "$GOV_SET" -eq 0 ]; then
  echo "  ✅ All cores already in 'performance' mode (or governor not available)."
fi

# ═══════════════════════════════════════════════
# 6. TCP STACK TUNING
# ═══════════════════════════════════════════════
echo ""
echo "── TCP Stack ──"

# Increase connection backlog for loopback
echo 65535 > /proc/sys/net/core/somaxconn 2>/dev/null || true
echo "  somaxconn: $(cat /proc/sys/net/core/somaxconn)"

# Enable TCP fastopen (client + server)
echo 3 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || true
echo "  tcp_fastopen: $(cat /proc/sys/net/ipv4/tcp_fastopen)"

# Optimize loopback/localhost
echo "  ✅ TCP tuned for benchmark load."

# ═══════════════════════════════════════════════
# 7. CLEANUP STALE CGROUPS
# ═══════════════════════════════════════════════
echo ""
echo "── Cgroups Cleanup ──"

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  # Remove any leftover benchmark/waf cgroups from previous runs
  for cg in benchmark waf; do
    if [ -d "/sys/fs/cgroup/$cg" ]; then
      # Move any processes back to root cgroup first
      if [ -f "/sys/fs/cgroup/$cg/cgroup.procs" ]; then
        while read -r pid; do
          echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
        done < /sys/fs/cgroup/$cg/cgroup.procs 2>/dev/null
      fi
      rmdir "/sys/fs/cgroup/$cg" 2>/dev/null && echo "  Removed stale cgroup: $cg" || true
    fi
  done

  # ═══════════════════════════════════════════════
  # 8. SETUP CGROUPS FOR TIER
  # ═══════════════════════════════════════════════
  echo ""
  echo "── Cgroups Setup (tier: $TIER) ──"

  case "$TIER" in
    min)
      WAF_CORES="0-1"
      BENCH_CORES="2"
      WAF_MEM_MAX="4294967296"    # 4GB
      BENCH_MEM_MAX="536870912"   # 512MB
      ;;
    mid)
      WAF_CORES="0-3"
      BENCH_CORES="4-5"
      WAF_MEM_MAX="8589934592"    # 8GB
      BENCH_MEM_MAX="1610612736"  # 1.5GB
      ;;
    full)
      WAF_CORES="0-5"
      BENCH_CORES="6"
      WAF_MEM_MAX="12884901888"   # 12GB
      BENCH_MEM_MAX="2147483648"  # 2GB
      ;;
  esac

  # Create WAF cgroup (priority first)
  mkdir -p /sys/fs/cgroup/waf
  echo "$WAF_CORES" > /sys/fs/cgroup/waf/cpuset.cpus
  echo "0" > /sys/fs/cgroup/waf/cpuset.mems
  echo "$WAF_MEM_MAX" > /sys/fs/cgroup/waf/memory.max
  # Disable swap for WAF cgroup
  echo 0 > /sys/fs/cgroup/waf/memory.swap.max 2>/dev/null || true
  echo "  WAF:    cores $WAF_CORES, memory $(($WAF_MEM_MAX / 1024 / 1024))MB"

  # Create Benchmark cgroup
  mkdir -p /sys/fs/cgroup/benchmark
  echo "$BENCH_CORES" > /sys/fs/cgroup/benchmark/cpuset.cpus
  echo "0" > /sys/fs/cgroup/benchmark/cpuset.mems
  echo "$BENCH_MEM_MAX" > /sys/fs/cgroup/benchmark/memory.max
  echo "  Bench:  cores $BENCH_CORES, memory $(($BENCH_MEM_MAX / 1024 / 1024))MB"

  echo ""
  echo "  ✅ Cgroups v2 configured for tier '$TIER'"
  echo "     WAF:    cpuset=$WAF_CORES  memory.max=$(($WAF_MEM_MAX / 1024 / 1024))MB"
  echo "     Bench:  cpuset=$BENCH_CORES  memory.max=$(($BENCH_MEM_MAX / 1024 / 1024))MB"
else
  echo "  ⚠️  cgroups v2 NOT available."
  echo "     CPU pinning will be done via taskset fallback."
  echo "     Results will be flagged NOISY."
fi

# ═══════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════
echo ""
echo "══════════════════════════════════════════════"
echo "  PRE-FLIGHT COMPLETE"
echo "══════════════════════════════════════════════"
echo "  Tier:       $TIER"
echo "  CPU cores:  $NPROC"
echo "  RAM:        ${MEM_TOTAL_GB}GB (${MEM_AVAIL_GB}GB available)"
echo "  Swap:       $(if [ "$SWAP_TOTAL_KB" -gt 0 ]; then echo '⚠️  ACTIVE'; else echo '✅ disabled'; fi)"
echo "  THP:        $(if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then cat /sys/kernel/mm/transparent_hugepage/enabled | grep -o '\[.*\]' | tr -d '[]'; else echo 'N/A'; fi)"
echo "  Governor:   $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')"
echo "  Cgroups:    $(if [ -f /sys/fs/cgroup/cgroup.controllers ]; then echo '✅ v2 active'; else echo '❌ unavailable'; fi)"
echo ""

# Print instructions for process assignment
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  echo "To assign processes to cgroups:"
  echo "  echo \$WAF_PID > /sys/fs/cgroup/waf/cgroup.procs"
  echo "  echo \$BENCH_PID > /sys/fs/cgroup/benchmark/cgroup.procs"
  echo ""
fi

echo "Ready for benchmark. Run: waf-benchmark -p c -o ./reports/phase_c"
