\# **LogNexus**

\## **Universal Log Pre-processing Framework**

\*\*SIH Problem Statement:\*\* SIH26156  

\*\*Team:\*\* **Origin**


LogNexus is a centralized log pre-processing framework designed to process heterogeneous logs from different sources and formats.


\### Key Features


\- Log ingestion from configured sources

\- Automatic log format detection

\- Source-specific parsing

\- Common field normalization

\- Event validation

\- Raw log preservation

\- Raw-to-normalized traceability using trace IDs

\- PostgreSQL-based storage

\- Web-based monitoring dashboard

\- Source profile management

\- AI-assisted field mapping concept for unknown sources



\### Architecture



```text

Log Sources

&#x20;    ↓

Ingestion

&#x20;    ↓

Format Detection

&#x20;    ↓

Parsing

&#x20;    ↓

Normalization

&#x20;    ↓

Validation

&#x20;    ↓

Raw + Normalized Storage

&#x20;    ↓

Dashboard / SIEM / Analytics

