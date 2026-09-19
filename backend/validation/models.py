from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    """
    Common normalized event model used by LogNexus.

    The model is source-independent. Fields that are not available
    for a particular source remain None, while source-specific fields
    can be preserved in extra_data.
    """

    # Event identification
    event_id: str | None = None
    timestamp: str | None = None

    # Source information
    source: str
    device: str | None = None

    # Event classification
    event_type: str
    severity: str | None = None

    # Network information, when available
    source_ip: str | None = None
    source_port: str | None = None
    destination_ip: str | None = None
    destination_port: str | None = None

    # User / identity information
    user_id: str | None = None
    user_name: str | None = None

    # Activity information
    action: str | None = None
    outcome: str | None = None

    # Human-readable / source message
    message: list = Field(default_factory=list)

    # Source-specific information that doesn't fit the common schema
    extra_data: dict = Field(default_factory=dict)