"Query 1 — Breach Frequency by Year
How has the volume of confirmed breaches trended over time?"

SELECT
    year,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN data_disclosure = 'Yes' THEN 1 ELSE 0 END) AS confirmed_breaches,
    ROUND(SUM(CASE WHEN data_disclosure = 'Yes' THEN 1 ELSE 0 END) * 100.0 
          / COUNT(*), 2) AS breach_confirmation_pct
FROM incidents
WHERE year BETWEEN 2010 AND 2025
GROUP BY year
ORDER BY year;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 2 — Industry Breach Concentration
Which industries are most frequently targeted?"

SELECT
    industry_name,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN data_disclosure = 'Yes' THEN 1 ELSE 0 END) AS confirmed_breaches,
    ROUND(SUM(CASE WHEN data_disclosure = 'Yes' THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS breach_rate_pct,
    SUM(CASE WHEN has_internal_actor = 1 THEN 1 ELSE 0 END) AS internal_actor_count,
    ROUND(SUM(CASE WHEN has_internal_actor = 1 THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS internal_actor_pct
FROM incidents
WHERE year BETWEEN 2010 AND 2025
  AND industry_name != 'Unknown'
GROUP BY industry_name
ORDER BY total_incidents DESC;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 3 — Attack Vector Dominance
What attack methods are most commonly used — hacking, malware, social engineering, insider misuse, or human error?"

SELECT
    action_type,
    COUNT(*) AS total_uses,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM actions), 2) AS pct_of_all_actions
FROM actions
JOIN incidents ON actions.incident_id = incidents.incident_id
WHERE incidents.year BETWEEN 2010 AND 2025
GROUP BY action_type
ORDER BY total_uses DESC;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 4 — Attack Vector Trend Over Time
How has the mix of attack methods shifted year over year?"

SELECT
    i.year,
    SUM(CASE WHEN a.action_type = 'hacking'  THEN 1 ELSE 0 END) AS hacking,
    SUM(CASE WHEN a.action_type = 'malware'  THEN 1 ELSE 0 END) AS malware,
    SUM(CASE WHEN a.action_type = 'social'   THEN 1 ELSE 0 END) AS social_engineering,
    SUM(CASE WHEN a.action_type = 'misuse'   THEN 1 ELSE 0 END) AS insider_misuse,
    SUM(CASE WHEN a.action_type = 'error'    THEN 1 ELSE 0 END) AS human_error,
    SUM(CASE WHEN a.action_type = 'physical' THEN 1 ELSE 0 END) AS physical
FROM actions a
JOIN incidents i ON a.incident_id = i.incident_id
WHERE i.year BETWEEN 2010 AND 2025
GROUP BY i.year
ORDER BY i.year;
----------------------------------------------------------------------------------------------------------------------------------------------

"Query 5 — Threat Actor Analysis
Who is behind the breaches — external attackers, insiders, or partners?"

SELECT
    ac.actor_type,
    ac.motive,
    COUNT(*) AS total_incidents,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM actors), 2) AS pct_of_all_actors
FROM actors ac
JOIN incidents i ON ac.incident_id = i.incident_id
WHERE i.year BETWEEN 2010 AND 2025
  AND ac.motive != 'Unknown'
GROUP BY ac.actor_type, ac.motive
ORDER BY total_incidents DESC
LIMIT 15;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 6 — Internal Actor Governance Failure by Industry
Option 3 reference — which industries have the highest proportion of insider-driven incidents, indicating governance failures?"

SELECT
    i.industry_name,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN i.has_internal_actor = 1 THEN 1 ELSE 0 END) AS internal_actor_incidents,
    ROUND(SUM(CASE WHEN i.has_internal_actor = 1 THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS internal_actor_pct,
    SUM(CASE WHEN i.has_external_actor = 1 THEN 1 ELSE 0 END) AS external_actor_incidents,
    ROUND(SUM(CASE WHEN i.has_external_actor = 1 THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS external_actor_pct
FROM incidents i
WHERE i.year BETWEEN 2010 AND 2025
  AND i.industry_name NOT IN ('Unknown', 'Other (000)')
GROUP BY i.industry_name
HAVING total_incidents >= 50
ORDER BY internal_actor_pct DESC;
----------------------------------------------------------------------------------------------------------------------------------------------

"Query 7 — Discovery Method by Industry
Option 3 reference — what proportion of breaches were discovered internally vs externally? Internal discovery signals stronger governance and detection capability."

SELECT
    i.industry_name,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN i.discovery_source = 'Internal' THEN 1 ELSE 0 END) AS internal_discovery,
    SUM(CASE WHEN i.discovery_source = 'External' THEN 1 ELSE 0 END) AS external_discovery,
    SUM(CASE WHEN i.discovery_source = 'Unknown'  THEN 1 ELSE 0 END) AS unknown_discovery,
    ROUND(SUM(CASE WHEN i.discovery_source = 'Internal' THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS internal_discovery_pct,
    ROUND(SUM(CASE WHEN i.discovery_source = 'External' THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS external_discovery_pct
FROM incidents i
WHERE i.year BETWEEN 2010 AND 2025
  AND i.industry_name NOT IN ('Unknown', 'Other (000)')
GROUP BY i.industry_name
HAVING total_incidents >= 50
ORDER BY internal_discovery_pct DESC;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 8 — Most Commonly Compromised Data Types
What categories of data are most at risk?"

SELECT
    dc.data_variety,
    COUNT(*) AS total_incidents,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM data_compromised), 2) AS pct_of_all_breaches
FROM data_compromised dc
JOIN incidents i ON dc.incident_id = i.incident_id
WHERE i.year BETWEEN 2010 AND 2025
  AND dc.data_variety != 'Unknown'
GROUP BY dc.data_variety
ORDER BY total_incidents DESC
LIMIT 15;
---------------------------------------------------------------------------------------------------------------------------------------------

"Query 9 — Organisation Size vs Breach Frequency
Option 3 reference — do larger organisations with more governance resources breach less frequently?"

SELECT
    employee_count,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN has_internal_actor = 1 THEN 1 ELSE 0 END) AS internal_actor_incidents,
    ROUND(SUM(CASE WHEN has_internal_actor = 1 THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS internal_actor_pct,
    ROUND(SUM(CASE WHEN data_disclosure = 'Yes' THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS breach_confirmation_pct
FROM incidents
WHERE year BETWEEN 2010 AND 2025
  AND employee_count NOT IN ('Unknown', 'Small', 'Large')
GROUP BY employee_count
ORDER BY total_incidents DESC;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 10 — Combined Governance Risk Score by Industry
Synthesises Queries 6 and 7 — industries ranked by combined internal actor rate and external discovery rate, both indicators of governance weakness"

SELECT
    industry_name,
    total_incidents,
    internal_actor_pct,
    external_discovery_pct,
    ROUND((internal_actor_pct + external_discovery_pct) / 2, 2) AS governance_risk_score
FROM (
    SELECT
        i.industry_name,
        COUNT(*) AS total_incidents,
        ROUND(SUM(CASE WHEN i.has_internal_actor = 1 THEN 1 ELSE 0 END) * 100.0
              / COUNT(*), 2) AS internal_actor_pct,
        ROUND(SUM(CASE WHEN i.discovery_source = 'External' THEN 1 ELSE 0 END) * 100.0
              / COUNT(*), 2) AS external_discovery_pct
    FROM incidents i
    WHERE i.year BETWEEN 2010 AND 2025
      AND i.industry_name NOT IN ('Unknown', 'Other (000)')
    GROUP BY i.industry_name
    HAVING total_incidents >= 50
)
ORDER BY governance_risk_score DESC;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 11 — Detection Capability Trend (MTTD Proxy)
Is the sector getting better or worse at detecting its own breaches over time?"

SELECT
    i.year,
    COUNT(*) AS total_incidents,
    SUM(CASE WHEN i.discovery_source = 'Internal' THEN 1 ELSE 0 END) AS self_detected,
    SUM(CASE WHEN i.discovery_source = 'External' THEN 1 ELSE 0 END) AS externally_detected,
    ROUND(SUM(CASE WHEN i.discovery_source = 'Internal' THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS self_detection_rate_pct,
    ROUND(SUM(CASE WHEN i.discovery_source = 'External' THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS external_detection_rate_pct
FROM incidents i
WHERE i.year BETWEEN 2010 AND 2025
GROUP BY i.year
ORDER BY i.year;
-----------------------------------------------------------------------------------------------------------------------------------------------

"Query 12 — Error vs Malicious Intent Ratio by Industry
Separates governance failures from targeted attacks — high error rates signal operational resilience gaps rather than sophisticated adversaries"

SELECT
    i.industry_name,
    COUNT(DISTINCT i.incident_id) AS total_incidents,
    SUM(CASE WHEN i.has_error = 1 AND i.has_external_actor = 0 THEN 1 ELSE 0 END) AS error_only_incidents,
    SUM(CASE WHEN i.has_hacking = 1 OR i.has_malware = 1 THEN 1 ELSE 0 END) AS malicious_incidents,
    ROUND(SUM(CASE WHEN i.has_error = 1 AND i.has_external_actor = 0 THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS error_rate_pct,
    ROUND(SUM(CASE WHEN i.has_hacking = 1 OR i.has_malware = 1 THEN 1 ELSE 0 END) * 100.0
          / COUNT(*), 2) AS malicious_rate_pct
FROM incidents i
WHERE i.year BETWEEN 2010 AND 2025
  AND i.industry_name NOT IN ('Unknown', 'Other (000)')
GROUP BY i.industry_name
HAVING total_incidents >= 50
ORDER BY error_rate_pct DESC;