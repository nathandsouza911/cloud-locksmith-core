-- Cloud Locksmith baseline schema (revision 20261110_baseline).
-- Generated from a schema-only pg_dump of a database migrated through the
-- original 77 revisions (head 20260804_workflow_runtime). Do not edit by hand:
-- add a new Alembic revision instead.
--
-- PostgreSQL database dump
--


-- Dumped from database version 15.17 (Debian 15.17-1.pgdg13+1)
-- Dumped by pg_dump version 15.17 (Debian 15.17-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: enforcementmode; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.enforcementmode AS ENUM (
    'AUDIT',
    'REPORT_ONLY',
    'ENFORCED'
);


--
-- Name: exposurestatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.exposurestatus AS ENUM (
    'ACTIVE',
    'RESOLVED'
);


--
-- Name: offboarding_session_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.offboarding_session_status AS ENUM (
    'PENDING',
    'IN_PROGRESS',
    'COMPLETED',
    'REVERSED'
);


--
-- Name: organization_plan_enum; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.organization_plan_enum AS ENUM (
    'FREE',
    'PRO',
    'MSP'
);


--
-- Name: organizationmode; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.organizationmode AS ENUM (
    'SINGLE',
    'MANAGED'
);


--
-- Name: remediationstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.remediationstatus AS ENUM (
    'PENDING',
    'APPROVED',
    'EXECUTING',
    'SUCCESS',
    'FAILED',
    'BLOCKED',
    'IGNORED'
);


--
-- Name: resolutionsource; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.resolutionsource AS ENUM (
    'SYSTEM',
    'EXTERNAL',
    'BASELINE_UPDATE',
    'OFFBOARDING'
);


--
-- Name: tenant_access_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.tenant_access_type AS ENUM (
    'SMB_OWNER',
    'MSP_MANAGER'
);


--
-- Name: ticket_note_author_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.ticket_note_author_type AS ENUM (
    'USER',
    'ADMIN'
);


--
-- Name: ticket_priority; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.ticket_priority AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH'
);


--
-- Name: ticket_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.ticket_status AS ENUM (
    'OPEN',
    'CLOSED'
);


--
-- Name: ticket_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.ticket_type AS ENUM (
    'BUG',
    'FEATURE',
    'SUPPORT',
    'BILLING',
    'OTHER'
);


--
-- Name: user_tenant_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.user_tenant_role AS ENUM (
    'OWNER',
    'ADMIN',
    'READ_ONLY'
);


--
-- Name: audit_log_immutability(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.audit_log_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- DELETE is unconditionally blocked.
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'audit_logs rows are immutable: DELETE is not permitted (id=%).',
            OLD.id;
    END IF;

    -- UPDATE: only allow the one-time write of sequence_hash / previous_hash.
    -- Every other column — including details — must be identical to the stored
    -- value.  IS NOT DISTINCT FROM handles NULLs correctly.
    IF (
        OLD.sequence_hash IS NULL
        AND NEW.sequence_hash IS NOT NULL
        AND OLD.id            = NEW.id
        AND OLD.tenant_id     = NEW.tenant_id
        AND OLD.action        = NEW.action
        AND OLD.actor         = NEW.actor
        AND OLD.target        = NEW.target
        AND OLD.status        = NEW.status
        AND OLD.created_at    = NEW.created_at
        AND (OLD.reason  IS NOT DISTINCT FROM NEW.reason)
        AND (OLD.details IS NOT DISTINCT FROM NEW.details)
    ) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'audit_logs rows are immutable: UPDATE is not permitted (id=%).',
        OLD.id;
END;
$$;


--
-- Name: prevent_campaign_audit_event_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_campaign_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
                IF OLD.sequence_hash IS NOT NULL THEN
                    RAISE EXCEPTION
                        'campaign_audit_events rows are immutable once sequence_hash is set';
                END IF;
                RETURN NEW;
            END;
            $$;


--
-- Name: prevent_notarization_receipt_status_reversion(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_notarization_receipt_status_reversion() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
                IF OLD.receipt_status = 'VERIFIED' AND NEW.receipt_status != 'VERIFIED' THEN
                    RAISE EXCEPTION
                        'campaign_notarization_receipts: receipt_status cannot be changed once VERIFIED';
                END IF;
                RETURN NEW;
            END;
            $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alerts (
    id integer NOT NULL,
    tenant_id character varying,
    alert_type character varying(100),
    severity character varying(20),
    message character varying(500),
    details json,
    created_at timestamp without time zone DEFAULT now(),
    resolved_at timestamp without time zone
);


--
-- Name: alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    id integer NOT NULL,
    tenant_id character varying,
    asset_type character varying(50),
    external_id character varying(255),
    asset_metadata json,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: assets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.assets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: assets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.assets_id_seq OWNED BY public.assets.id;


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    action character varying NOT NULL,
    actor character varying NOT NULL,
    target character varying NOT NULL,
    status character varying NOT NULL,
    reason character varying,
    details json NOT NULL,
    created_at timestamp without time zone,
    previous_hash character varying(64),
    sequence_hash character varying(64)
);


--
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_logs_id_seq OWNED BY public.audit_logs.id;


--
-- Name: break_glass_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.break_glass_accounts (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    user_external_id character varying NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: break_glass_accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.break_glass_accounts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: break_glass_accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.break_glass_accounts_id_seq OWNED BY public.break_glass_accounts.id;


--
-- Name: break_glass_usage_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.break_glass_usage_events (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    user_principal_name character varying(255),
    source_event_id character varying(255) NOT NULL,
    source character varying(64) NOT NULL,
    event_type character varying(64) NOT NULL,
    "timestamp" timestamp without time zone NOT NULL,
    ip_address character varying(128),
    location character varying(255),
    status character varying(32) NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: break_glass_usage_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.break_glass_usage_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: break_glass_usage_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.break_glass_usage_events_id_seq OWNED BY public.break_glass_usage_events.id;


--
-- Name: campaign_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_audit_events (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    event_type character varying(64) NOT NULL,
    actor character varying(255) NOT NULL,
    payload json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sequence_hash character varying(64),
    previous_hash character varying(64)
);


--
-- Name: campaign_notarization_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_notarization_receipts (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    manifest_hash character varying(64) NOT NULL,
    signature_hash character varying(64) NOT NULL,
    provider character varying(64) NOT NULL,
    provider_receipt_token text NOT NULL,
    provider_timestamp timestamp with time zone,
    receipt_status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    verification_metadata json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone
);


--
-- Name: campaign_scheduled_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_scheduled_jobs (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    scheduled_at timestamp with time zone NOT NULL,
    state character varying DEFAULT 'PENDING'::character varying NOT NULL,
    lease_owner character varying,
    lease_expires_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 3 NOT NULL,
    execution_started_at timestamp with time zone,
    execution_completed_at timestamp with time zone,
    failure_reason character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_campaign_scheduled_jobs_state CHECK ((state IN ('PENDING', 'CLAIMED', 'EXECUTING', 'COMPLETED', 'FAILED')))
);


--
-- Name: campaign_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_templates (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    name character varying NOT NULL,
    created_by character varying NOT NULL,
    control_ids json NOT NULL,
    target_tenant_ids json NOT NULL,
    dry_run boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: campaign_tenant_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_tenant_tasks (
    id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    compliance_result_id integer NOT NULL,
    control_id character varying NOT NULL,
    status character varying DEFAULT 'PLANNED'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    audit_log_id uuid,
    result_json json,
    error character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: compliance_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_reports (
    id integer NOT NULL,
    tenant_id character varying,
    framework character varying(50),
    format character varying(10),
    file_path character varying(255),
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: compliance_reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_reports_id_seq OWNED BY public.compliance_reports.id;


--
-- Name: compliance_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_results (
    drift_detected_at timestamp without time zone,
    last_verified_at timestamp without time zone,
    last_remediated_at timestamp without time zone,
    remediation_count_7d integer NOT NULL,
    drift_lock boolean NOT NULL,
    enforcement_mode public.enforcementmode DEFAULT 'AUDIT'::public.enforcementmode NOT NULL,
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    control_id character varying(100),
    framework character varying(50),
    passed boolean,
    severity character varying(50),
    evidence jsonb,
    approval_requirement character varying(32),
    decision_status character varying(32),
    evaluated_at timestamp without time zone DEFAULT now(),
    resource_id character varying(255) DEFAULT ''::character varying NOT NULL,
    execution_attempts integer NOT NULL,
    block_reason character varying(64),
    exposure_status public.exposurestatus NOT NULL,
    remediation_status public.remediationstatus NOT NULL,
    drift_count integer NOT NULL,
    resolved_at timestamp without time zone,
    resolved_by public.resolutionsource,
    last_seen_at timestamp without time zone,
    first_seen_at timestamp without time zone,
    resource_type character varying(32) DEFAULT 'TENANT'::character varying NOT NULL,
    acknowledged boolean DEFAULT false NOT NULL,
    acknowledged_at timestamp without time zone,
    acknowledged_by character varying(255)
);


--
-- Name: compliance_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_results_id_seq OWNED BY public.compliance_results.id;


--
-- Name: compliance_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_snapshots (
    id integer NOT NULL,
    tenant_id character varying,
    framework character varying(50),
    score integer,
    summary json,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: compliance_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_snapshots_id_seq OWNED BY public.compliance_snapshots.id;


--
-- Name: conditional_access_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conditional_access_policies (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    policy_id character varying NOT NULL,
    display_name character varying,
    state character varying,
    requires_mfa boolean,
    blocks_legacy_auth boolean,
    raw_policy json,
    created_at timestamp without time zone,
    policy_version integer NOT NULL,
    managed_by character varying(64)
);


--
-- Name: conditional_access_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.conditional_access_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: conditional_access_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.conditional_access_policies_id_seq OWNED BY public.conditional_access_policies.id;


--
-- Name: control_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.control_executions (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    control_id character varying(100) NOT NULL,
    mode character varying(20) NOT NULL,
    rollout_phase character varying(20) NOT NULL,
    status character varying(20) NOT NULL,
    policies_created jsonb NOT NULL,
    policies_updated jsonb NOT NULL,
    snapshot_id uuid,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    verified boolean NOT NULL,
    managed_policy_ids jsonb NOT NULL
);


--
-- Name: control_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.control_snapshots (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    control_id character varying(100) NOT NULL,
    policies jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    managed_policy_ids jsonb NOT NULL
);


--
-- Name: control_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.control_states (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    control_id character varying(100) NOT NULL,
    mode character varying(20) NOT NULL,
    rollout_phase character varying(20) NOT NULL,
    rollout_percentage integer NOT NULL,
    target_group_id character varying(255),
    policy_version integer NOT NULL,
    status character varying(20) NOT NULL,
    last_applied_at timestamp without time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    managed_policy_ids jsonb NOT NULL
);


--
-- Name: drift_notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drift_notifications (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    compliance_result_id integer NOT NULL,
    verification_id uuid NOT NULL,
    verification_event_id uuid NOT NULL,
    control_id character varying(100) NOT NULL,
    notification_severity character varying(20) NOT NULL,
    is_repeat_drift boolean DEFAULT false NOT NULL,
    previous_status character varying(30) NOT NULL,
    affects_readiness_score boolean NOT NULL,
    affects_underwriting_evidence boolean NOT NULL,
    confidence_tier_before character varying(2) NOT NULL,
    summary character varying(500) NOT NULL,
    acknowledged boolean DEFAULT false NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_drift_notification_confidence_tier CHECK ((confidence_tier_before IN ('A', 'B'))),
    CONSTRAINT ck_drift_notification_severity CHECK ((notification_severity IN ('CRITICAL', 'HIGH', 'MEDIUM')))
);


--
-- Name: evidence_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_reports (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    score integer NOT NULL,
    score_band character varying NOT NULL,
    reporting_period character varying NOT NULL,
    generated_at timestamp without time zone,
    report_payload_id integer
);


--
-- Name: evidence_reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.evidence_reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: evidence_reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.evidence_reports_id_seq OWNED BY public.evidence_reports.id;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id character varying NOT NULL,
    tenant_id character varying,
    check_id character varying,
    severity character varying,
    title character varying,
    evidence json,
    detected_at timestamp without time zone
);


--
-- Name: ingestion_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingestion_snapshots (
    id character varying NOT NULL,
    tenant_id character varying NOT NULL,
    source character varying NOT NULL,
    payload json NOT NULL,
    collected_at timestamp without time zone
);


--
-- Name: license_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.license_findings (
    id character varying(36) NOT NULL,
    tenant_id character varying NOT NULL,
    type character varying(64) NOT NULL,
    user_id character varying(255),
    license_type character varying(64) NOT NULL,
    estimated_monthly_cost integer NOT NULL,
    metadata json NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: license_snapshot; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.license_snapshot (
    id character varying(36) NOT NULL,
    tenant_id character varying NOT NULL,
    "timestamp" timestamp without time zone NOT NULL,
    raw_data json NOT NULL
);


--
-- Name: managed_rollout_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_rollout_groups (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    graph_group_id character varying NOT NULL,
    control_id character varying NOT NULL,
    managed boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: mfa_posture; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mfa_posture (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    user_external_id character varying NOT NULL,
    user_principal_name character varying,
    mfa_registered boolean,
    mfa_enforced boolean,
    created_at timestamp without time zone
);


--
-- Name: mfa_posture_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mfa_posture_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mfa_posture_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mfa_posture_id_seq OWNED BY public.mfa_posture.id;


--
-- Name: msp_security_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.msp_security_baselines (
    organization_id character varying,
    baseline_name character varying,
    controls json,
    created_at timestamp without time zone DEFAULT now(),
    is_active boolean DEFAULT false NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: notification_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_targets (
    id integer NOT NULL,
    tenant_id character varying,
    channel character varying(50),
    destination character varying(500),
    enabled boolean
);


--
-- Name: notification_targets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.notification_targets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notification_targets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.notification_targets_id_seq OWNED BY public.notification_targets.id;


--
-- Name: oauth_state_nonces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_state_nonces (
    nonce character varying(64) NOT NULL,
    flow character varying(32),
    created_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone
);


--
-- Name: offboarding_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.offboarding_sessions (
    id uuid NOT NULL,
    tenant_id character varying(255) NOT NULL,
    control_id character varying(100) NOT NULL,
    resource_id character varying(255) NOT NULL,
    status public.offboarding_session_status DEFAULT 'PENDING'::public.offboarding_session_status NOT NULL,
    steps json DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    snapshot json,
    offboarding_completed_at timestamp without time zone,
    offboarding_reversed_at timestamp without time zone
);


--
-- Name: organization_plan_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_plan_audit (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    old_plan public.organization_plan_enum NOT NULL,
    new_plan public.organization_plan_enum NOT NULL,
    changed_at timestamp without time zone NOT NULL,
    changed_by character varying
);


--
-- Name: organization_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_usage (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    remediations_executed integer DEFAULT 0 NOT NULL,
    insurance_reports_generated integer DEFAULT 0 NOT NULL,
    fleet_operations integer DEFAULT 0 NOT NULL,
    usage_period_start timestamp without time zone NOT NULL,
    cyber_insurance_reports_generated integer DEFAULT 0 NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid NOT NULL,
    name character varying NOT NULL,
    mode public.organizationmode NOT NULL,
    created_at timestamp without time zone NOT NULL,
    last_fleet_scan_at timestamp without time zone,
    fleet_mfa_enforcement_enabled boolean NOT NULL,
    fleet_mfa_mode character varying(32),
    fleet_policy_hash character varying(64),
    plan public.organization_plan_enum DEFAULT 'FREE'::public.organization_plan_enum NOT NULL
);


--
-- Name: pending_oauth_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_oauth_sessions (
    id uuid NOT NULL,
    state text NOT NULL,
    initiating_user_id uuid,
    initiating_session_identifier character varying(128),
    intent character varying(32) NOT NULL,
    expected_tenant_id character varying(255),
    resolved_tenant_id character varying(255),
    frontend_path character varying(255),
    callback_payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    confirmed_at timestamp with time zone
);


--
-- Name: platform_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_users (
    id uuid NOT NULL,
    email character varying NOT NULL,
    password_hash character varying,
    role character varying,
    organization_id uuid NOT NULL,
    created_at timestamp without time zone,
    has_accepted_terms boolean DEFAULT false NOT NULL,
    oid character varying(64),
    auth_provider character varying DEFAULT 'microsoft'::character varying NOT NULL,
    verified_at timestamp without time zone,
    CONSTRAINT auth_provider_check CHECK ((auth_provider IN ('microsoft', 'password'))),
    CONSTRAINT password_required_check CHECK ((((auth_provider)::text <> 'password'::text) OR (password_hash IS NOT NULL)))
);


--
-- Name: posture_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.posture_snapshots (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    posture json NOT NULL,
    security_score integer NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: posture_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.posture_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: posture_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.posture_snapshots_id_seq OWNED BY public.posture_snapshots.id;


--
-- Name: remediation_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_actions (
    id integer NOT NULL,
    tenant_id character varying,
    action_type character varying(100),
    payload json,
    status character varying(50),
    created_at timestamp without time zone DEFAULT now(),
    executed_at timestamp without time zone
);


--
-- Name: remediation_actions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.remediation_actions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: remediation_actions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.remediation_actions_id_seq OWNED BY public.remediation_actions.id;


--
-- Name: remediation_audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_audit_logs (
    id uuid NOT NULL,
    compliance_result_id integer NOT NULL,
    tenant_id character varying NOT NULL,
    control_id character varying NOT NULL,
    resource_type character varying NOT NULL,
    resource_id character varying NOT NULL,
    decision character varying NOT NULL,
    confidence double precision NOT NULL,
    explanation_summary character varying NOT NULL,
    explanation_factors json NOT NULL,
    explanation_risk_note character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    approved boolean,
    approved_at timestamp with time zone,
    approved_by character varying,
    execution_status character varying,
    executed_at timestamp with time zone,
    verified boolean,
    verified_at timestamp with time zone,
    rolled_back boolean
);


--
-- Name: remediation_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_campaigns (
    id uuid NOT NULL,
    organization_id uuid NOT NULL,
    created_by character varying NOT NULL,
    control_ids json NOT NULL,
    max_remediation_level character varying DEFAULT 'SAFE'::character varying NOT NULL,
    status character varying DEFAULT 'PLAN'::character varying NOT NULL,
    dry_run boolean DEFAULT false NOT NULL,
    plan_hash character varying,
    approved_plan_hash character varying,
    approved_items json,
    approved_by character varying,
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    scheduled_at timestamp with time zone
);


--
-- Name: remediation_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_snapshots (
    id integer NOT NULL,
    compliance_result_id integer NOT NULL,
    state jsonb NOT NULL,
    created_at timestamp without time zone NOT NULL,
    policy_snapshot json,
    policy_version integer,
    policy_hash character varying(64),
    state_after jsonb
);


--
-- Name: remediation_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.remediation_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: remediation_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.remediation_snapshots_id_seq OWNED BY public.remediation_snapshots.id;


--
-- Name: remediation_verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_verifications (
    id uuid NOT NULL,
    execution_id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    compliance_result_id integer NOT NULL,
    control_id character varying NOT NULL,
    status character varying DEFAULT 'PENDING'::character varying NOT NULL,
    confidence double precision DEFAULT '0'::double precision NOT NULL,
    first_verified_at timestamp with time zone,
    last_verified_at timestamp with time zone,
    last_checked_at timestamp with time zone,
    verification_count integer DEFAULT 0 NOT NULL,
    evidence_json json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    drift_count integer DEFAULT 0 NOT NULL
);


--
-- Name: report_payloads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_payloads (
    id integer NOT NULL,
    tenant_id character varying NOT NULL,
    report_type character varying(32) NOT NULL,
    generated_at timestamp without time zone DEFAULT now() NOT NULL,
    payload jsonb NOT NULL,
    content_hash character varying(64) NOT NULL,
    score integer,
    previous_report_hash character varying(64),
    chain_hash character varying(64),
    attestation_json jsonb,
    attestation_signature character varying(64)
);


--
-- Name: report_payloads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.report_payloads_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: report_payloads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.report_payloads_id_seq OWNED BY public.report_payloads.id;


--
-- Name: report_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_schedules (
    id integer NOT NULL,
    tenant_id character varying,
    report_type character varying,
    frequency character varying,
    last_run_at timestamp without time zone,
    next_run_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: report_schedules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.report_schedules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: report_schedules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.report_schedules_id_seq OWNED BY public.report_schedules.id;


--
-- Name: signing_key_metadata; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signing_key_metadata (
    id uuid NOT NULL,
    key_id character varying(64) NOT NULL,
    algorithm character varying(32) NOT NULL,
    status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    public_key_pem text NOT NULL,
    public_key_fingerprint character varying(64) NOT NULL,
    encrypted_private_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    key_metadata json DEFAULT '{}'::json NOT NULL
);


--
-- Name: support_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.support_tickets (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    user_id uuid NOT NULL,
    type public.ticket_type NOT NULL,
    status public.ticket_status DEFAULT 'OPEN'::public.ticket_status NOT NULL,
    priority public.ticket_priority,
    subject text NOT NULL,
    description text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: tenant_deletion_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_deletion_logs (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    tenant_name character varying(255),
    deleted_by_user_id character varying NOT NULL,
    deleted_at timestamp without time zone NOT NULL
);


--
-- Name: tenant_oauth; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_oauth (
    tenant_id character varying NOT NULL,
    provider character varying NOT NULL,
    access_token character varying NOT NULL,
    refresh_token character varying,
    expires_at timestamp without time zone NOT NULL,
    scopes json NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id character varying NOT NULL,
    tenant_name character varying(255),
    domain character varying(255),
    provider character varying(50) NOT NULL,
    oauth_state character varying(255),
    oauth_token json,
    is_active boolean,
    asset_flags json NOT NULL,
    last_scheduler_run timestamp without time zone,
    scheduler_failures integer,
    scheduler_backoff_until timestamp without time zone,
    onboarded_at timestamp without time zone,
    last_scan_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone,
    last_delegated_auth_at timestamp without time zone,
    organization_id uuid,
    provider_credentials jsonb
);


--
-- Name: ticket_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ticket_notes (
    id uuid NOT NULL,
    ticket_id uuid NOT NULL,
    author_type public.ticket_note_author_type NOT NULL,
    author_id uuid,
    content text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: user_tenant_access; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_tenant_access (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    tenant_id character varying(255) NOT NULL,
    role public.user_tenant_role DEFAULT 'OWNER'::public.user_tenant_role NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    organization_id uuid,
    access_type public.tenant_access_type
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    tenant_id character varying,
    external_id character varying(255),
    email character varying(255),
    display_name character varying(255),
    last_login timestamp without time zone,
    is_admin boolean,
    created_at timestamp without time zone DEFAULT now(),
    is_break_glass boolean DEFAULT false NOT NULL
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: verification_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verification_events (
    id uuid NOT NULL,
    verification_id uuid NOT NULL,
    previous_status character varying,
    new_status character varying NOT NULL,
    reason character varying,
    evidence_json json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: workflow_review_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_review_decisions (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    workflow_type character varying(64) NOT NULL,
    control_id character varying(100) NOT NULL,
    resource_type character varying(32) DEFAULT 'TENANT'::character varying NOT NULL,
    resource_id character varying(255) DEFAULT ''::character varying NOT NULL,
    decision character varying(16) NOT NULL,
    reason text,
    reviewed_by character varying(255) NOT NULL,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL,
    evidence_hash character varying(64) NOT NULL,
    superseded_at timestamp with time zone,
    superseded_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    workflow_run_id uuid
);


--
-- Name: workflow_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_runs (
    id uuid NOT NULL,
    tenant_id character varying NOT NULL,
    workflow_definition_key character varying(64) NOT NULL,
    trigger character varying(32) DEFAULT 'LAZY'::character varying NOT NULL,
    state character varying(32) DEFAULT 'CREATED'::character varying NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_by character varying(255) NOT NULL,
    current_stage character varying(64),
    summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: workflow_stages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_stages (
    id uuid NOT NULL,
    workflow_run_id uuid NOT NULL,
    stage_key character varying(64) NOT NULL,
    sequence integer DEFAULT 0 NOT NULL,
    state character varying(16) DEFAULT 'PENDING'::character varying NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- Name: assets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets ALTER COLUMN id SET DEFAULT nextval('public.assets_id_seq'::regclass);


--
-- Name: audit_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs ALTER COLUMN id SET DEFAULT nextval('public.audit_logs_id_seq'::regclass);


--
-- Name: break_glass_accounts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_accounts ALTER COLUMN id SET DEFAULT nextval('public.break_glass_accounts_id_seq'::regclass);


--
-- Name: break_glass_usage_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_usage_events ALTER COLUMN id SET DEFAULT nextval('public.break_glass_usage_events_id_seq'::regclass);


--
-- Name: compliance_reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_reports ALTER COLUMN id SET DEFAULT nextval('public.compliance_reports_id_seq'::regclass);


--
-- Name: compliance_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results ALTER COLUMN id SET DEFAULT nextval('public.compliance_results_id_seq'::regclass);


--
-- Name: compliance_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_snapshots ALTER COLUMN id SET DEFAULT nextval('public.compliance_snapshots_id_seq'::regclass);


--
-- Name: conditional_access_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conditional_access_policies ALTER COLUMN id SET DEFAULT nextval('public.conditional_access_policies_id_seq'::regclass);


--
-- Name: evidence_reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_reports ALTER COLUMN id SET DEFAULT nextval('public.evidence_reports_id_seq'::regclass);


--
-- Name: mfa_posture id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_posture ALTER COLUMN id SET DEFAULT nextval('public.mfa_posture_id_seq'::regclass);


--
-- Name: notification_targets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_targets ALTER COLUMN id SET DEFAULT nextval('public.notification_targets_id_seq'::regclass);


--
-- Name: posture_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_snapshots ALTER COLUMN id SET DEFAULT nextval('public.posture_snapshots_id_seq'::regclass);


--
-- Name: remediation_actions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_actions ALTER COLUMN id SET DEFAULT nextval('public.remediation_actions_id_seq'::regclass);


--
-- Name: remediation_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_snapshots ALTER COLUMN id SET DEFAULT nextval('public.remediation_snapshots_id_seq'::regclass);


--
-- Name: report_payloads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_payloads ALTER COLUMN id SET DEFAULT nextval('public.report_payloads_id_seq'::regclass);


--
-- Name: report_schedules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_schedules ALTER COLUMN id SET DEFAULT nextval('public.report_schedules_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: break_glass_accounts break_glass_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_accounts
    ADD CONSTRAINT break_glass_accounts_pkey PRIMARY KEY (id);


--
-- Name: break_glass_usage_events break_glass_usage_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_usage_events
    ADD CONSTRAINT break_glass_usage_events_pkey PRIMARY KEY (id);


--
-- Name: campaign_audit_events campaign_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_audit_events
    ADD CONSTRAINT campaign_audit_events_pkey PRIMARY KEY (id);


--
-- Name: campaign_notarization_receipts campaign_notarization_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_notarization_receipts
    ADD CONSTRAINT campaign_notarization_receipts_pkey PRIMARY KEY (id);


--
-- Name: campaign_scheduled_jobs campaign_scheduled_jobs_campaign_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_scheduled_jobs
    ADD CONSTRAINT campaign_scheduled_jobs_campaign_id_key UNIQUE (campaign_id);


--
-- Name: campaign_scheduled_jobs campaign_scheduled_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_scheduled_jobs
    ADD CONSTRAINT campaign_scheduled_jobs_pkey PRIMARY KEY (id);


--
-- Name: campaign_templates campaign_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_templates
    ADD CONSTRAINT campaign_templates_pkey PRIMARY KEY (id);


--
-- Name: campaign_tenant_tasks campaign_tenant_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_tenant_tasks
    ADD CONSTRAINT campaign_tenant_tasks_pkey PRIMARY KEY (id);


--
-- Name: compliance_reports compliance_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_reports
    ADD CONSTRAINT compliance_reports_pkey PRIMARY KEY (id);


--
-- Name: compliance_results compliance_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT compliance_results_pkey PRIMARY KEY (id);


--
-- Name: compliance_snapshots compliance_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_snapshots
    ADD CONSTRAINT compliance_snapshots_pkey PRIMARY KEY (id);


--
-- Name: conditional_access_policies conditional_access_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conditional_access_policies
    ADD CONSTRAINT conditional_access_policies_pkey PRIMARY KEY (id);


--
-- Name: control_executions control_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_executions
    ADD CONSTRAINT control_executions_pkey PRIMARY KEY (id);


--
-- Name: control_snapshots control_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_snapshots
    ADD CONSTRAINT control_snapshots_pkey PRIMARY KEY (id);


--
-- Name: control_states control_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_states
    ADD CONSTRAINT control_states_pkey PRIMARY KEY (id);


--
-- Name: drift_notifications drift_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_pkey PRIMARY KEY (id);


--
-- Name: evidence_reports evidence_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_reports
    ADD CONSTRAINT evidence_reports_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: ingestion_snapshots ingestion_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingestion_snapshots
    ADD CONSTRAINT ingestion_snapshots_pkey PRIMARY KEY (id);


--
-- Name: license_findings license_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_findings
    ADD CONSTRAINT license_findings_pkey PRIMARY KEY (id);


--
-- Name: license_snapshot license_snapshot_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_snapshot
    ADD CONSTRAINT license_snapshot_pkey PRIMARY KEY (id);


--
-- Name: managed_rollout_groups managed_rollout_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_rollout_groups
    ADD CONSTRAINT managed_rollout_groups_pkey PRIMARY KEY (id);


--
-- Name: mfa_posture mfa_posture_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_posture
    ADD CONSTRAINT mfa_posture_pkey PRIMARY KEY (id);


--
-- Name: msp_security_baselines msp_security_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.msp_security_baselines
    ADD CONSTRAINT msp_security_baselines_pkey PRIMARY KEY (id);


--
-- Name: notification_targets notification_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_targets
    ADD CONSTRAINT notification_targets_pkey PRIMARY KEY (id);


--
-- Name: oauth_state_nonces oauth_state_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_state_nonces
    ADD CONSTRAINT oauth_state_nonces_pkey PRIMARY KEY (nonce);


--
-- Name: offboarding_sessions offboarding_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.offboarding_sessions
    ADD CONSTRAINT offboarding_sessions_pkey PRIMARY KEY (id);


--
-- Name: organization_plan_audit organization_plan_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_plan_audit
    ADD CONSTRAINT organization_plan_audit_pkey PRIMARY KEY (id);


--
-- Name: organization_usage organization_usage_organization_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_usage
    ADD CONSTRAINT organization_usage_organization_id_key UNIQUE (organization_id);


--
-- Name: organization_usage organization_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_usage
    ADD CONSTRAINT organization_usage_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: pending_oauth_sessions pending_oauth_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_oauth_sessions
    ADD CONSTRAINT pending_oauth_sessions_pkey PRIMARY KEY (id);


--
-- Name: platform_users platform_users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_users
    ADD CONSTRAINT platform_users_email_key UNIQUE (email);


--
-- Name: platform_users platform_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_users
    ADD CONSTRAINT platform_users_pkey PRIMARY KEY (id);


--
-- Name: posture_snapshots posture_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_snapshots
    ADD CONSTRAINT posture_snapshots_pkey PRIMARY KEY (id);


--
-- Name: remediation_actions remediation_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_actions
    ADD CONSTRAINT remediation_actions_pkey PRIMARY KEY (id);


--
-- Name: remediation_audit_logs remediation_audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_audit_logs
    ADD CONSTRAINT remediation_audit_logs_pkey PRIMARY KEY (id);


--
-- Name: remediation_campaigns remediation_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_campaigns
    ADD CONSTRAINT remediation_campaigns_pkey PRIMARY KEY (id);


--
-- Name: remediation_snapshots remediation_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_snapshots
    ADD CONSTRAINT remediation_snapshots_pkey PRIMARY KEY (id);


--
-- Name: remediation_verifications remediation_verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_verifications
    ADD CONSTRAINT remediation_verifications_pkey PRIMARY KEY (id);


--
-- Name: report_payloads report_payloads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_payloads
    ADD CONSTRAINT report_payloads_pkey PRIMARY KEY (id);


--
-- Name: report_schedules report_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_schedules
    ADD CONSTRAINT report_schedules_pkey PRIMARY KEY (id);


--
-- Name: signing_key_metadata signing_key_metadata_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_key_metadata
    ADD CONSTRAINT signing_key_metadata_key_id_key UNIQUE (key_id);


--
-- Name: signing_key_metadata signing_key_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_key_metadata
    ADD CONSTRAINT signing_key_metadata_pkey PRIMARY KEY (id);


--
-- Name: support_tickets support_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_tickets
    ADD CONSTRAINT support_tickets_pkey PRIMARY KEY (id);


--
-- Name: tenant_deletion_logs tenant_deletion_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_deletion_logs
    ADD CONSTRAINT tenant_deletion_logs_pkey PRIMARY KEY (id);


--
-- Name: tenant_oauth tenant_oauth_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_oauth
    ADD CONSTRAINT tenant_oauth_pkey PRIMARY KEY (tenant_id, provider);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: ticket_notes ticket_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_notes
    ADD CONSTRAINT ticket_notes_pkey PRIMARY KEY (id);


--
-- Name: break_glass_usage_events uq_break_glass_usage_event_tenant_source; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_usage_events
    ADD CONSTRAINT uq_break_glass_usage_event_tenant_source UNIQUE (tenant_id, source_event_id);


--
-- Name: campaign_tenant_tasks uq_campaign_task_finding; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_tenant_tasks
    ADD CONSTRAINT uq_campaign_task_finding UNIQUE (campaign_id, tenant_id, compliance_result_id);


--
-- Name: compliance_results uq_compliance_result_tenant_control_resource; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT uq_compliance_result_tenant_control_resource UNIQUE (tenant_id, control_id, resource_id);


--
-- Name: control_states uq_control_states_tenant_control; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_states
    ADD CONSTRAINT uq_control_states_tenant_control UNIQUE (tenant_id, control_id);


--
-- Name: pending_oauth_sessions uq_pending_oauth_sessions_state; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_oauth_sessions
    ADD CONSTRAINT uq_pending_oauth_sessions_state UNIQUE (state);


--
-- Name: managed_rollout_groups uq_rollout_group_tenant_control; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_rollout_groups
    ADD CONSTRAINT uq_rollout_group_tenant_control UNIQUE (tenant_id, control_id);


--
-- Name: user_tenant_access uq_user_tenant_access_user_tenant; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tenant_access
    ADD CONSTRAINT uq_user_tenant_access_user_tenant UNIQUE (user_id, tenant_id);


--
-- Name: workflow_stages uq_workflow_stage_run_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_stages
    ADD CONSTRAINT uq_workflow_stage_run_key UNIQUE (workflow_run_id, stage_key);


--
-- Name: user_tenant_access user_tenant_access_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tenant_access
    ADD CONSTRAINT user_tenant_access_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: verification_events verification_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_events
    ADD CONSTRAINT verification_events_pkey PRIMARY KEY (id);


--
-- Name: workflow_review_decisions workflow_review_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_review_decisions
    ADD CONSTRAINT workflow_review_decisions_pkey PRIMARY KEY (id);


--
-- Name: workflow_runs workflow_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_pkey PRIMARY KEY (id);


--
-- Name: workflow_stages workflow_stages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_stages
    ADD CONSTRAINT workflow_stages_pkey PRIMARY KEY (id);


--
-- Name: idx_user_tenant_access_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_tenant_access_organization_id ON public.user_tenant_access USING btree (organization_id);


--
-- Name: idx_user_tenant_access_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_tenant_access_tenant_id ON public.user_tenant_access USING btree (tenant_id);


--
-- Name: idx_user_tenant_access_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_tenant_access_user_id ON public.user_tenant_access USING btree (user_id);


--
-- Name: ix_alerts_alert_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alerts_alert_type ON public.alerts USING btree (alert_type);


--
-- Name: ix_alerts_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alerts_tenant_id ON public.alerts USING btree (tenant_id);


--
-- Name: ix_assets_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_assets_id ON public.assets USING btree (id);


--
-- Name: ix_audit_logs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_logs_id ON public.audit_logs USING btree (id);


--
-- Name: ix_audit_logs_sequence_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_logs_sequence_hash ON public.audit_logs USING btree (sequence_hash);


--
-- Name: ix_audit_logs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_logs_tenant_id ON public.audit_logs USING btree (tenant_id);


--
-- Name: ix_break_glass_usage_events_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_break_glass_usage_events_tenant_id ON public.break_glass_usage_events USING btree (tenant_id);


--
-- Name: ix_break_glass_usage_events_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_break_glass_usage_events_timestamp ON public.break_glass_usage_events USING btree ("timestamp");


--
-- Name: ix_break_glass_usage_events_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_break_glass_usage_events_user_id ON public.break_glass_usage_events USING btree (user_id);


--
-- Name: ix_break_glass_usage_events_user_principal_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_break_glass_usage_events_user_principal_name ON public.break_glass_usage_events USING btree (user_principal_name);


--
-- Name: ix_campaign_audit_events_campaign_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_audit_events_campaign_created ON public.campaign_audit_events USING btree (campaign_id, created_at);


--
-- Name: ix_campaign_audit_events_campaign_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_audit_events_campaign_id ON public.campaign_audit_events USING btree (campaign_id);


--
-- Name: ix_campaign_audit_events_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_audit_events_organization_id ON public.campaign_audit_events USING btree (organization_id);


--
-- Name: ix_campaign_audit_events_sequence_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_audit_events_sequence_hash ON public.campaign_audit_events USING btree (sequence_hash);


--
-- Name: ix_campaign_notarization_receipts_campaign_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_notarization_receipts_campaign_id ON public.campaign_notarization_receipts USING btree (campaign_id);


--
-- Name: ix_campaign_notarization_receipts_campaign_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_notarization_receipts_campaign_org ON public.campaign_notarization_receipts USING btree (campaign_id, organization_id);


--
-- Name: ix_campaign_notarization_receipts_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_notarization_receipts_organization_id ON public.campaign_notarization_receipts USING btree (organization_id);


--
-- Name: ix_campaign_scheduled_jobs_campaign_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_campaign_scheduled_jobs_campaign_id ON public.campaign_scheduled_jobs USING btree (campaign_id);


--
-- Name: ix_campaign_scheduled_jobs_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_scheduled_jobs_organization_id ON public.campaign_scheduled_jobs USING btree (organization_id);


--
-- Name: ix_campaign_scheduled_jobs_state_lease_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_scheduled_jobs_state_lease_expires_at ON public.campaign_scheduled_jobs USING btree (state, lease_expires_at);


--
-- Name: ix_campaign_scheduled_jobs_state_scheduled_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_scheduled_jobs_state_scheduled_at ON public.campaign_scheduled_jobs USING btree (state, scheduled_at);


--
-- Name: ix_campaign_templates_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_templates_organization_id ON public.campaign_templates USING btree (organization_id);


--
-- Name: ix_campaign_tenant_tasks_campaign_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_tenant_tasks_campaign_id ON public.campaign_tenant_tasks USING btree (campaign_id);


--
-- Name: ix_campaign_tenant_tasks_compliance_result_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_tenant_tasks_compliance_result_id ON public.campaign_tenant_tasks USING btree (compliance_result_id);


--
-- Name: ix_campaign_tenant_tasks_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_campaign_tenant_tasks_tenant_id ON public.campaign_tenant_tasks USING btree (tenant_id);


--
-- Name: ix_compliance_reports_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_reports_tenant_id ON public.compliance_reports USING btree (tenant_id);


--
-- Name: ix_compliance_results_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_control_id ON public.compliance_results USING btree (control_id);


--
-- Name: ix_compliance_results_exposure_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_exposure_status ON public.compliance_results USING btree (exposure_status);


--
-- Name: ix_compliance_results_remediation_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_remediation_status ON public.compliance_results USING btree (remediation_status);


--
-- Name: ix_compliance_results_resource_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_resource_id ON public.compliance_results USING btree (resource_id);


--
-- Name: ix_compliance_results_resource_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_resource_type ON public.compliance_results USING btree (resource_type);


--
-- Name: ix_compliance_results_tenant_control_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_tenant_control_resource ON public.compliance_results USING btree (tenant_id, control_id, resource_id);


--
-- Name: ix_compliance_results_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_results_tenant_id ON public.compliance_results USING btree (tenant_id);


--
-- Name: ix_compliance_snapshots_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_snapshots_tenant_id ON public.compliance_snapshots USING btree (tenant_id);


--
-- Name: ix_control_executions_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_executions_control_id ON public.control_executions USING btree (control_id);


--
-- Name: ix_control_executions_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_executions_snapshot_id ON public.control_executions USING btree (snapshot_id);


--
-- Name: ix_control_executions_tenant_control; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_executions_tenant_control ON public.control_executions USING btree (tenant_id, control_id);


--
-- Name: ix_control_executions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_executions_tenant_id ON public.control_executions USING btree (tenant_id);


--
-- Name: ix_control_snapshots_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_snapshots_control_id ON public.control_snapshots USING btree (control_id);


--
-- Name: ix_control_snapshots_tenant_control; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_snapshots_tenant_control ON public.control_snapshots USING btree (tenant_id, control_id);


--
-- Name: ix_control_snapshots_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_snapshots_tenant_id ON public.control_snapshots USING btree (tenant_id);


--
-- Name: ix_control_states_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_states_control_id ON public.control_states USING btree (control_id);


--
-- Name: ix_control_states_tenant_control; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_states_tenant_control ON public.control_states USING btree (tenant_id, control_id);


--
-- Name: ix_control_states_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_control_states_tenant_id ON public.control_states USING btree (tenant_id);


--
-- Name: ix_drift_notifications_compliance_result_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_compliance_result_id ON public.drift_notifications USING btree (compliance_result_id);


--
-- Name: ix_drift_notifications_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_control_id ON public.drift_notifications USING btree (control_id);


--
-- Name: ix_drift_notifications_tenant_ack_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_tenant_ack_created ON public.drift_notifications USING btree (tenant_id, acknowledged, created_at);


--
-- Name: ix_drift_notifications_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_tenant_id ON public.drift_notifications USING btree (tenant_id);


--
-- Name: ix_drift_notifications_verification_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_drift_notifications_verification_id ON public.drift_notifications USING btree (verification_id);


--
-- Name: ix_evidence_reports_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_reports_id ON public.evidence_reports USING btree (id);


--
-- Name: ix_evidence_reports_report_payload_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_reports_report_payload_id ON public.evidence_reports USING btree (report_payload_id);


--
-- Name: ix_evidence_reports_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_evidence_reports_tenant_id ON public.evidence_reports USING btree (tenant_id);


--
-- Name: ix_findings_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_tenant_id ON public.findings USING btree (tenant_id);


--
-- Name: ix_ingestion_snapshots_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ingestion_snapshots_tenant_id ON public.ingestion_snapshots USING btree (tenant_id);


--
-- Name: ix_license_findings_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_license_findings_created_at ON public.license_findings USING btree (created_at);


--
-- Name: ix_license_findings_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_license_findings_tenant_id ON public.license_findings USING btree (tenant_id);


--
-- Name: ix_license_findings_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_license_findings_type ON public.license_findings USING btree (type);


--
-- Name: ix_license_findings_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_license_findings_user_id ON public.license_findings USING btree (user_id);


--
-- Name: ix_license_snapshot_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_license_snapshot_tenant_id ON public.license_snapshot USING btree (tenant_id);


--
-- Name: ix_license_snapshot_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_license_snapshot_timestamp ON public.license_snapshot USING btree ("timestamp");


--
-- Name: ix_managed_rollout_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_managed_rollout_groups_tenant_id ON public.managed_rollout_groups USING btree (tenant_id);


--
-- Name: ix_msp_security_baselines_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_msp_security_baselines_organization_id ON public.msp_security_baselines USING btree (organization_id);


--
-- Name: ix_notification_targets_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_notification_targets_tenant_id ON public.notification_targets USING btree (tenant_id);


--
-- Name: ix_oauth_state_nonces_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_oauth_state_nonces_created_at ON public.oauth_state_nonces USING btree (created_at);


--
-- Name: ix_offboarding_sessions_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_offboarding_sessions_control_id ON public.offboarding_sessions USING btree (control_id);


--
-- Name: ix_offboarding_sessions_resource_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_offboarding_sessions_resource_id ON public.offboarding_sessions USING btree (resource_id);


--
-- Name: ix_offboarding_sessions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_offboarding_sessions_tenant_id ON public.offboarding_sessions USING btree (tenant_id);


--
-- Name: ix_pending_oauth_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_pending_oauth_sessions_expires_at ON public.pending_oauth_sessions USING btree (expires_at);


--
-- Name: ix_pending_oauth_sessions_initiating_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_pending_oauth_sessions_initiating_user_id ON public.pending_oauth_sessions USING btree (initiating_user_id);


--
-- Name: ix_pending_oauth_sessions_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_pending_oauth_sessions_intent ON public.pending_oauth_sessions USING btree (intent);


--
-- Name: ix_pending_oauth_sessions_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_pending_oauth_sessions_state ON public.pending_oauth_sessions USING btree (state);


--
-- Name: ix_pending_oauth_sessions_user_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_pending_oauth_sessions_user_intent ON public.pending_oauth_sessions USING btree (initiating_user_id, intent);


--
-- Name: ix_platform_users_oid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_platform_users_oid ON public.platform_users USING btree (oid);


--
-- Name: ix_posture_snapshots_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_posture_snapshots_tenant_id ON public.posture_snapshots USING btree (tenant_id);


--
-- Name: ix_remediation_actions_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_actions_id ON public.remediation_actions USING btree (id);


--
-- Name: ix_remediation_audit_logs_compliance_result_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_audit_logs_compliance_result_id ON public.remediation_audit_logs USING btree (compliance_result_id);


--
-- Name: ix_remediation_audit_logs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_audit_logs_tenant_id ON public.remediation_audit_logs USING btree (tenant_id);


--
-- Name: ix_remediation_campaigns_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_campaigns_organization_id ON public.remediation_campaigns USING btree (organization_id);


--
-- Name: ix_remediation_snapshots_compliance_result_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_snapshots_compliance_result_id ON public.remediation_snapshots USING btree (compliance_result_id);


--
-- Name: ix_remediation_snapshots_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_snapshots_id ON public.remediation_snapshots USING btree (id);


--
-- Name: ix_remediation_snapshots_policy_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_snapshots_policy_hash ON public.remediation_snapshots USING btree (policy_hash);


--
-- Name: ix_remediation_verifications_compliance_result_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_verifications_compliance_result_id ON public.remediation_verifications USING btree (compliance_result_id);


--
-- Name: ix_remediation_verifications_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_verifications_control_id ON public.remediation_verifications USING btree (control_id);


--
-- Name: ix_remediation_verifications_execution_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_remediation_verifications_execution_id ON public.remediation_verifications USING btree (execution_id);


--
-- Name: ix_remediation_verifications_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_verifications_tenant_id ON public.remediation_verifications USING btree (tenant_id);


--
-- Name: ix_report_payloads_chain_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_payloads_chain_hash ON public.report_payloads USING btree (chain_hash);


--
-- Name: ix_report_payloads_content_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_payloads_content_hash ON public.report_payloads USING btree (content_hash);


--
-- Name: ix_report_payloads_generated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_payloads_generated_at ON public.report_payloads USING btree (generated_at);


--
-- Name: ix_report_payloads_report_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_payloads_report_type ON public.report_payloads USING btree (report_type);


--
-- Name: ix_report_payloads_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_payloads_tenant_id ON public.report_payloads USING btree (tenant_id);


--
-- Name: ix_report_schedules_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_schedules_tenant_id ON public.report_schedules USING btree (tenant_id);


--
-- Name: ix_review_decisions_tenant_workflow_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_review_decisions_tenant_workflow_active ON public.workflow_review_decisions USING btree (tenant_id, workflow_type, superseded_at);


--
-- Name: ix_signing_key_metadata_key_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_signing_key_metadata_key_id ON public.signing_key_metadata USING btree (key_id);


--
-- Name: ix_signing_key_metadata_public_key_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_signing_key_metadata_public_key_fingerprint ON public.signing_key_metadata USING btree (public_key_fingerprint);


--
-- Name: ix_support_tickets_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_support_tickets_status ON public.support_tickets USING btree (status);


--
-- Name: ix_support_tickets_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_support_tickets_tenant_id ON public.support_tickets USING btree (tenant_id);


--
-- Name: ix_support_tickets_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_support_tickets_type ON public.support_tickets USING btree (type);


--
-- Name: ix_support_tickets_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_support_tickets_user_id ON public.support_tickets USING btree (user_id);


--
-- Name: ix_tenant_deletion_logs_deleted_by_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_deletion_logs_deleted_by_user_id ON public.tenant_deletion_logs USING btree (deleted_by_user_id);


--
-- Name: ix_tenant_deletion_logs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_deletion_logs_tenant_id ON public.tenant_deletion_logs USING btree (tenant_id);


--
-- Name: ix_tenant_oauth_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenant_oauth_tenant_id ON public.tenant_oauth USING btree (tenant_id);


--
-- Name: ix_tenants_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tenants_id ON public.tenants USING btree (id);


--
-- Name: ix_ticket_notes_ticket_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ticket_notes_ticket_id ON public.ticket_notes USING btree (ticket_id);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: ix_users_external_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_users_external_id ON public.users USING btree (external_id);


--
-- Name: ix_users_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_users_id ON public.users USING btree (id);


--
-- Name: ix_verification_events_verification_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_verification_events_verification_id ON public.verification_events USING btree (verification_id);


--
-- Name: ix_workflow_review_decisions_control_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_review_decisions_control_id ON public.workflow_review_decisions USING btree (control_id);


--
-- Name: ix_workflow_review_decisions_evidence_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_review_decisions_evidence_hash ON public.workflow_review_decisions USING btree (evidence_hash);


--
-- Name: ix_workflow_review_decisions_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_review_decisions_run_id ON public.workflow_review_decisions USING btree (workflow_run_id);


--
-- Name: ix_workflow_review_decisions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_review_decisions_tenant_id ON public.workflow_review_decisions USING btree (tenant_id);


--
-- Name: ix_workflow_review_decisions_workflow_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_review_decisions_workflow_type ON public.workflow_review_decisions USING btree (workflow_type);


--
-- Name: ix_workflow_runs_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_runs_state ON public.workflow_runs USING btree (state);


--
-- Name: ix_workflow_runs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_runs_tenant_id ON public.workflow_runs USING btree (tenant_id);


--
-- Name: ix_workflow_runs_tenant_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_runs_tenant_state ON public.workflow_runs USING btree (tenant_id, state);


--
-- Name: ix_workflow_runs_workflow_definition_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_runs_workflow_definition_key ON public.workflow_runs USING btree (workflow_definition_key);


--
-- Name: ix_workflow_stages_run_sequence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_stages_run_sequence ON public.workflow_stages USING btree (workflow_run_id, sequence);


--
-- Name: ix_workflow_stages_workflow_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_workflow_stages_workflow_run_id ON public.workflow_stages USING btree (workflow_run_id);


--
-- Name: unique_smb_owner_per_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_smb_owner_per_tenant ON public.user_tenant_access USING btree (tenant_id) WHERE (access_type = 'SMB_OWNER'::public.tenant_access_type);


--
-- Name: uq_active_review_decision; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_active_review_decision ON public.workflow_review_decisions USING btree (tenant_id, workflow_type, control_id, resource_id) WHERE (superseded_at IS NULL);


--
-- Name: uq_active_workflow_run; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_active_workflow_run ON public.workflow_runs USING btree (tenant_id, workflow_definition_key) WHERE (state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED'));


--
-- Name: audit_logs audit_log_immutability_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_immutability_trigger BEFORE DELETE OR UPDATE ON public.audit_logs FOR EACH ROW EXECUTE FUNCTION public.audit_log_immutability();


--
-- Name: campaign_audit_events enforce_campaign_audit_event_immutability; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_campaign_audit_event_immutability BEFORE UPDATE ON public.campaign_audit_events FOR EACH ROW EXECUTE FUNCTION public.prevent_campaign_audit_event_mutation();


--
-- Name: campaign_notarization_receipts enforce_notarization_receipt_immutability; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_notarization_receipt_immutability BEFORE UPDATE ON public.campaign_notarization_receipts FOR EACH ROW EXECUTE FUNCTION public.prevent_notarization_receipt_status_reversion();


--
-- Name: alerts alerts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: assets assets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: break_glass_accounts break_glass_accounts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_accounts
    ADD CONSTRAINT break_glass_accounts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: break_glass_usage_events break_glass_usage_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.break_glass_usage_events
    ADD CONSTRAINT break_glass_usage_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: campaign_scheduled_jobs campaign_scheduled_jobs_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_scheduled_jobs
    ADD CONSTRAINT campaign_scheduled_jobs_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.remediation_campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_templates campaign_templates_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_templates
    ADD CONSTRAINT campaign_templates_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: campaign_tenant_tasks campaign_tenant_tasks_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_tenant_tasks
    ADD CONSTRAINT campaign_tenant_tasks_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.remediation_campaigns(id) ON DELETE CASCADE;


--
-- Name: compliance_reports compliance_reports_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_reports
    ADD CONSTRAINT compliance_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: compliance_results compliance_results_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_results
    ADD CONSTRAINT compliance_results_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: compliance_snapshots compliance_snapshots_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_snapshots
    ADD CONSTRAINT compliance_snapshots_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: conditional_access_policies conditional_access_policies_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conditional_access_policies
    ADD CONSTRAINT conditional_access_policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: control_executions control_executions_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_executions
    ADD CONSTRAINT control_executions_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES public.control_snapshots(id) ON DELETE SET NULL;


--
-- Name: control_executions control_executions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_executions
    ADD CONSTRAINT control_executions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: control_snapshots control_snapshots_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_snapshots
    ADD CONSTRAINT control_snapshots_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: control_states control_states_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_states
    ADD CONSTRAINT control_states_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: drift_notifications drift_notifications_compliance_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_compliance_result_id_fkey FOREIGN KEY (compliance_result_id) REFERENCES public.compliance_results(id);


--
-- Name: drift_notifications drift_notifications_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: drift_notifications drift_notifications_verification_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_verification_event_id_fkey FOREIGN KEY (verification_event_id) REFERENCES public.verification_events(id);


--
-- Name: drift_notifications drift_notifications_verification_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drift_notifications
    ADD CONSTRAINT drift_notifications_verification_id_fkey FOREIGN KEY (verification_id) REFERENCES public.remediation_verifications(id);


--
-- Name: evidence_reports evidence_reports_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_reports
    ADD CONSTRAINT evidence_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: evidence_reports fk_evidence_reports_report_payload_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_reports
    ADD CONSTRAINT fk_evidence_reports_report_payload_id FOREIGN KEY (report_payload_id) REFERENCES public.report_payloads(id) ON DELETE SET NULL;


--
-- Name: workflow_review_decisions fk_review_decision_workflow_run; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_review_decisions
    ADD CONSTRAINT fk_review_decision_workflow_run FOREIGN KEY (workflow_run_id) REFERENCES public.workflow_runs(id) ON DELETE SET NULL;


--
-- Name: tenant_oauth fk_tenant_oauth_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_oauth
    ADD CONSTRAINT fk_tenant_oauth_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: license_findings license_findings_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_findings
    ADD CONSTRAINT license_findings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: license_snapshot license_snapshot_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_snapshot
    ADD CONSTRAINT license_snapshot_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: managed_rollout_groups managed_rollout_groups_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_rollout_groups
    ADD CONSTRAINT managed_rollout_groups_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: mfa_posture mfa_posture_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_posture
    ADD CONSTRAINT mfa_posture_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: notification_targets notification_targets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_targets
    ADD CONSTRAINT notification_targets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: offboarding_sessions offboarding_sessions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.offboarding_sessions
    ADD CONSTRAINT offboarding_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: organization_plan_audit organization_plan_audit_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_plan_audit
    ADD CONSTRAINT organization_plan_audit_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: organization_usage organization_usage_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_usage
    ADD CONSTRAINT organization_usage_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: pending_oauth_sessions pending_oauth_sessions_initiating_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_oauth_sessions
    ADD CONSTRAINT pending_oauth_sessions_initiating_user_id_fkey FOREIGN KEY (initiating_user_id) REFERENCES public.platform_users(id) ON DELETE CASCADE;


--
-- Name: platform_users platform_users_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_users
    ADD CONSTRAINT platform_users_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: posture_snapshots posture_snapshots_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.posture_snapshots
    ADD CONSTRAINT posture_snapshots_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: remediation_actions remediation_actions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_actions
    ADD CONSTRAINT remediation_actions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: remediation_audit_logs remediation_audit_logs_compliance_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_audit_logs
    ADD CONSTRAINT remediation_audit_logs_compliance_result_id_fkey FOREIGN KEY (compliance_result_id) REFERENCES public.compliance_results(id);


--
-- Name: remediation_audit_logs remediation_audit_logs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_audit_logs
    ADD CONSTRAINT remediation_audit_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: remediation_campaigns remediation_campaigns_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_campaigns
    ADD CONSTRAINT remediation_campaigns_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: remediation_snapshots remediation_snapshots_compliance_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_snapshots
    ADD CONSTRAINT remediation_snapshots_compliance_result_id_fkey FOREIGN KEY (compliance_result_id) REFERENCES public.compliance_results(id) ON DELETE CASCADE;


--
-- Name: remediation_verifications remediation_verifications_compliance_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_verifications
    ADD CONSTRAINT remediation_verifications_compliance_result_id_fkey FOREIGN KEY (compliance_result_id) REFERENCES public.compliance_results(id);


--
-- Name: remediation_verifications remediation_verifications_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_verifications
    ADD CONSTRAINT remediation_verifications_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.remediation_audit_logs(id) ON DELETE CASCADE;


--
-- Name: remediation_verifications remediation_verifications_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_verifications
    ADD CONSTRAINT remediation_verifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: support_tickets support_tickets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_tickets
    ADD CONSTRAINT support_tickets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: support_tickets support_tickets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_tickets
    ADD CONSTRAINT support_tickets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.platform_users(id) ON DELETE CASCADE;


--
-- Name: tenants tenants_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: ticket_notes ticket_notes_ticket_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ticket_notes
    ADD CONSTRAINT ticket_notes_ticket_id_fkey FOREIGN KEY (ticket_id) REFERENCES public.support_tickets(id) ON DELETE CASCADE;


--
-- Name: user_tenant_access user_tenant_access_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tenant_access
    ADD CONSTRAINT user_tenant_access_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- Name: user_tenant_access user_tenant_access_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tenant_access
    ADD CONSTRAINT user_tenant_access_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: user_tenant_access user_tenant_access_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_tenant_access
    ADD CONSTRAINT user_tenant_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.platform_users(id) ON DELETE CASCADE;


--
-- Name: users users_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: verification_events verification_events_verification_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_events
    ADD CONSTRAINT verification_events_verification_id_fkey FOREIGN KEY (verification_id) REFERENCES public.remediation_verifications(id) ON DELETE CASCADE;


--
-- Name: workflow_review_decisions workflow_review_decisions_superseded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_review_decisions
    ADD CONSTRAINT workflow_review_decisions_superseded_by_fkey FOREIGN KEY (superseded_by) REFERENCES public.workflow_review_decisions(id) ON DELETE SET NULL;


--
-- Name: workflow_review_decisions workflow_review_decisions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_review_decisions
    ADD CONSTRAINT workflow_review_decisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: workflow_runs workflow_runs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: workflow_stages workflow_stages_workflow_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_stages
    ADD CONSTRAINT workflow_stages_workflow_run_id_fkey FOREIGN KEY (workflow_run_id) REFERENCES public.workflow_runs(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--
