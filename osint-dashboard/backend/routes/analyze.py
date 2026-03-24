from fastapi import APIRouter, HTTPException, status

from models.schemas import AnalyzeRequest, AnalyzeResponse, StoredResult
from services.ai_summary import generate_summary
from services.domain_osint import get_domain_intelligence
from services.email_osint import get_email_intelligence
from services.graph_builder import build_graph
from services.input_analyzer import InMemoryResultStore, InputAnalyzer
from services.username_osint import get_username_intelligence

router = APIRouter(prefix="", tags=["analysis"])
store = InMemoryResultStore()


@router.post("/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_202_ACCEPTED)
def analyze_input(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Classify and queue the input for deeper OSINT modules."""

    try:
        response = InputAnalyzer.classify(payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    details: dict[str, object] = {"step": "input_analyzer", "message": response.message}
    status_value = "classified"

    # STEP 2 enrichment: run domain OSINT immediately when the target is a domain.
    if response.input_type.value == "domain":
        try:
            details["domain_intelligence"] = get_domain_intelligence(response.normalized_query)
            status_value = "domain_enriched"
        except ValueError as exc:
            # Defensive: domain inputs should already be valid after classification.
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    # STEP 3 enrichment: run email breach intelligence for email targets.
    elif response.input_type.value == "email":
        try:
            details["email_intelligence"] = get_email_intelligence(response.normalized_query)
            status_value = "email_enriched"
        except ValueError as exc:
            # Defensive: email inputs should already be valid after classification.
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    # STEP 4 enrichment: run username footprint intelligence for username targets.
    elif response.input_type.value == "username":
        try:
            details["username_intelligence"] = get_username_intelligence(response.normalized_query)
            status_value = "username_enriched"
        except ValueError as exc:
            # Defensive: username inputs should already be valid after classification.
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    # STEP 5 enrichment: convert findings into graph nodes/edges for visualization.
    details["graph"] = build_graph(
        {
            "query": response.normalized_query,
            "input_type": response.input_type.value,
            "details": details,
        }
    )
    details["summary"] = generate_summary(
        {
            "query": response.normalized_query,
            "input_type": response.input_type.value,
            "details": details,
        }
    )

    store.save(
        StoredResult(
            request_id=response.request_id,
            query=response.normalized_query,
            input_type=response.input_type,
            status=status_value,
            details=details,
        )
    )
    return response


@router.get("/results/{request_id}", response_model=StoredResult)
def get_result(request_id: str) -> StoredResult:
    """Fetch analysis status/result by request id."""

    result = store.get(request_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not found")
    return result
