"""
ScanChunk model — maps to existing Supabase 'scan_chunks' table.
"""

import uuid
from sqlalchemy import Column, String, Integer, ForeignKey, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base import Base


class ScanChunk(Base):
    __tablename__ = "scan_chunks"

    chunk_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    file_name = Column(String(512), nullable=False)
    chunk_index = Column(Integer, default=0)
    token_size = Column(Integer, default=0)
    chunk_content = Column(Text, nullable=True)  # Cleared after processing
    flagged_by_rule = Column(JSON, nullable=True)

    scan = relationship("Scan", back_populates="chunks")

    def __repr__(self) -> str:
        return f"<ScanChunk {self.chunk_id} file={self.file_name}>"
