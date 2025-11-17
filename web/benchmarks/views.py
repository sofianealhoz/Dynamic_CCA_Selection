from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

@login_required
@require_GET
def results(request):
    with open(RESULTS_CSV, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Si tu veux filtrer par utilisateur (si tu stockes une colonne launched_by)
    user_runs = [row for row in rows if row["launched_by"] == request.user.username]

    return JsonResponse({"runs": user_runs})

@login_required
@require_POST
def launch_benchmark(request):
    profile_id = request.POST.get("profile_id")
    run_id = str(uuid.uuid4())

    append_to_csv(run_id, profile_id, request.user.username, status="RUNNING")

    try:
        subprocess.run(
            ["python3", "run_all_benchmarks.py"],
            check=True,
        )
        status = "SUCCESS"
    except subprocess.CalledProcessError as exc:
        status = "FAILED"

    update_csv_run(run_id, status=status, artifacts="result.csv")

    return JsonResponse({"run_id": run_id, "status": status})