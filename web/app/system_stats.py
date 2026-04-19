import psutil


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def host_stats(disk_path: str = "/opt/kumavpn") -> dict:
    """Lee RAM/CPU del kernel del host (cgroups no aisla /proc) y disco vía
    statvfs sobre una ruta bind-mounted desde el host (devuelve la fs real)."""
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.3)
    disk = psutil.disk_usage(disk_path)

    return {
        "ram": {
            "used": mem.used,
            "total": mem.total,
            "pct": round(mem.percent, 1),
            "used_h": fmt_bytes(mem.used),
            "total_h": fmt_bytes(mem.total),
        },
        "cpu": {
            "pct": round(cpu, 1),
            "cores": psutil.cpu_count(logical=True),
        },
        "disk": {
            "used": disk.used,
            "total": disk.total,
            "pct": round(disk.percent, 1),
            "used_h": fmt_bytes(disk.used),
            "total_h": fmt_bytes(disk.total),
        },
    }
