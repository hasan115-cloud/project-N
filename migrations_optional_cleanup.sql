-- OPTIONAL one-time cleanup — NOT part of schema.sql, never run automatically.
--
-- Versions before 1.5 wrote a history row for EVERY link found on every page the user
-- viewed (bulk link scanning), which flooded URL History with URLs nobody visited.
-- 1.5 no longer does this. This removes the historical rows from those sources.
--
-- 1) PREVIEW what would be removed (safe, read-only):
select source, count(*) from url_events
where source in ('extension-link', 'gmail-content', 'extension-bulk')
group by source;

-- 2) Then, if the numbers look right, run the delete inside a transaction:
-- begin;
-- delete from url_events where source in ('extension-link', 'gmail-content', 'extension-bulk');
-- commit;
--
-- Alerts raised for blocked links are kept (they are real detections).
