-- Recreates the campaign tables dropped by 20261120_drop_campaigns (empty).
-- Copied verbatim from 20261110_baseline_schema.sql; data and MSP_MANAGER rows are not restored.

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
-- Name: remediation_campaigns remediation_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_campaigns
    ADD CONSTRAINT remediation_campaigns_pkey PRIMARY KEY (id);


--
-- Name: campaign_tenant_tasks uq_campaign_task_finding; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_tenant_tasks
    ADD CONSTRAINT uq_campaign_task_finding UNIQUE (campaign_id, tenant_id, compliance_result_id);


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
-- Name: ix_remediation_campaigns_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_remediation_campaigns_organization_id ON public.remediation_campaigns USING btree (organization_id);


--
-- Name: campaign_audit_events enforce_campaign_audit_event_immutability; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_campaign_audit_event_immutability BEFORE UPDATE ON public.campaign_audit_events FOR EACH ROW EXECUTE FUNCTION public.prevent_campaign_audit_event_mutation();


--
-- Name: campaign_notarization_receipts enforce_notarization_receipt_immutability; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enforce_notarization_receipt_immutability BEFORE UPDATE ON public.campaign_notarization_receipts FOR EACH ROW EXECUTE FUNCTION public.prevent_notarization_receipt_status_reversion();


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
-- Name: remediation_campaigns remediation_campaigns_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_campaigns
    ADD CONSTRAINT remediation_campaigns_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


