Context & Objective

Analysed 10,586 confirmed security incidents from the VERIS Community Database, a publicly maintained repository of real-world breach disclosures, to identify breach patterns, dominant attack vectors, threat actor behaviour, and organisational resilience signals across industries and time. The project was designed to bridge technical breach data with governance accountability, directly extending the analytical themes of published research on board and senior management cybersecurity oversight responsibilities.

How the Project Was Conducted

Built a Python parsing pipeline to extract and normalise six structured tables from raw JSON incident files into a SQLite database, covering incidents, actions, actors, compromised data types, affected assets, and discovery methods. Wrote 12 structured SQL queries covering breach frequency trends, industry concentration, attack vector evolution, threat actor motives, internal actor rates, discovery capability, and a composite governance risk score. Delivered a three-page executive Power BI dashboard connected directly to the parsed dataset.

Key Findings

10,586 confirmed incidents across 2010–2025, with breach confirmation rates rising from 36% in 2010 to 99% by 2023, reflecting improved reporting maturity globally 
Healthcare and Public Administration account for nearly half of all incidents; Public Administration carries the highest internal actor rate at 65%, signalling systemic insider threat governance failures
Hacking is the dominant attack vector at 28% of all actions, but error-driven incidents account for 46% of Public Administration breaches, indicating operational governance failures rather than sophisticated external attacks
Self-detection rates peaked at 30% in 2018 and collapsed to under 5% by 2023–2025, while external detection surged to over 90%, a sector-wide deterioration in internal detection capability
Financial motive drives over 85% of external attacks; espionage accounts for the majority of state-affiliated incidents

Governance Framework Reference

The resilience and governance analysis on Page 3 is informed by the four-dimension resilience framework, detection capability, governance oversight, operational controls, and external dependency, operationalises the governance responsibilities identified in the systematic literature review, demonstrating how published academic findings can be applied to real-world breach data.
