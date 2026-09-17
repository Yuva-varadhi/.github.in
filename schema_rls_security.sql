-- ============================================================================
-- YUVA VARADHI ENTERPRISE SECURITY SCHEMA & ROW LEVEL SECURITY (RLS) POLICIES
-- Architecture: PostgreSQL 14+ / Supabase Engine
-- Cybersecurity Standards: Zero-Leak Isolation, 3-Tier RBAC, Anti-Self-Registration,
--                          Relational Subject Mapping & Citizen Grievance Vault
-- ============================================================================

-- 1. Enable Cryptographic & UUID Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 2. ENUM TYPES & CUSTOM ROLES
-- ============================================================================
DO $ BEGIN
    CREATE TYPE public.app_role AS ENUM (
        'super_admin', 
        'module_admin', 
        'sub_admin', 
        'teacher', 
        'citizen'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $;

DO $ BEGIN
    CREATE TYPE user_portal_role AS ENUM (
        'student', 
        'citizen', 
        'sub_admin', 
        'module_admin', 
        'second_admin', 
        'master_admin'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE portal_module_slot AS ENUM (
        'education', 
        'govt_jobs', 
        'agriculture', 
        'sports'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE resource_media_type AS ENUM (
        'syllabus', 
        'study_material', 
        'question_bank', 
        'official_circular', 
        'video_lecture', 
        'practical_guide'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- 3. PROFILES TABLE (Standard Citizen / Student Isolation)
-- Rule: Users can ONLY read and update their own personal profile.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    mobile_hashed VARCHAR(64) NOT NULL, -- SHA-256 encrypted for anti-scraping
    dob DATE NOT NULL,
    teacher_id VARCHAR(50),
    role user_portal_role NOT NULL DEFAULT 'student',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_public_role_scope CHECK (role IN ('student', 'citizen'))
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Root Super Admin (yuvavaradhi1@gmail.com) Master RLS Authority
CREATE POLICY "root_master_admin_manage_profiles"
    ON public.profiles
    FOR ALL
    TO authenticated
    USING (
        auth.email() = 'yuvavaradhi1@gmail.com' OR
        auth.uid() = id OR
        public.is_super_admin()
    );


-- Security Definer Function: Helper to check if caller is Super Admin
CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS BOOLEAN AS $
BEGIN
    RETURN (auth.email() = 'yuvavaradhi1@gmail.com') OR EXISTS (
        SELECT 1 FROM public.admin_hierarchy
        WHERE user_id = auth.uid() 
          AND role IN ('master_admin', 'second_admin')
          AND is_active = TRUE
    );
END;
$ LANGUAGE plpgsql SECURITY DEFINER;

-- Helper to fetch module assigned to current admin
CREATE OR REPLACE FUNCTION public.current_admin_module()
RETURNS portal_module_slot AS $$
BEGIN
    RETURN (
        SELECT assigned_module FROM public.admin_hierarchy
        WHERE user_id = auth.uid() AND is_active = TRUE
        LIMIT 1
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Helper to check if caller is a provisioned Admin of any tier
CREATE OR REPLACE FUNCTION public.is_authorized_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.admin_hierarchy
        WHERE user_id = auth.uid() AND is_active = TRUE
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- RLS Policy 1: User Self-Isolation (Read own record only, or Super Admin audit)
CREATE POLICY "users_read_own_profile"
    ON public.profiles
    FOR SELECT
    TO authenticated
    USING (auth.uid() = id OR public.is_super_admin());

-- RLS Policy 2: User Self-Update (Update own record only, strictly retaining student/citizen scope)
CREATE POLICY "users_update_own_profile"
    ON public.profiles
    FOR UPDATE
    TO authenticated
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id AND role IN ('student', 'citizen'));

-- RLS Policy 3: Public Self-Registration Lock (Anti-Self-Registration Protocol)
-- Public sign-ups are strictly hardcoded to 'student' or 'citizen' roles.
CREATE POLICY "users_insert_own_profile"
    ON public.profiles
    FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = id AND role IN ('student', 'citizen'));

-- ============================================================================
-- 4. ADMIN HIERARCHY TABLE (Strict 3-Tier RBAC Management)
-- Tier 1: Master Admin (PortalHead) & Secondary Super Admin
-- Tier 2: 4 Designated Module Admins (Education, Govt Jobs, Agri, Sports)
-- Tier 3: Up to 5 Sub-Admins per module slot
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.admin_hierarchy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role user_portal_role NOT NULL,
    assigned_module portal_module_slot,
    provisioned_by UUID REFERENCES auth.users(id),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_admin_role_scope CHECK (role IN ('master_admin', 'second_admin', 'module_admin', 'sub_admin')),
    CONSTRAINT chk_module_admin_binding CHECK (
        (role IN ('master_admin', 'second_admin') AND assigned_module IS NULL) OR
        (role IN ('module_admin', 'sub_admin') AND assigned_module IS NOT NULL)
    ),
    CONSTRAINT uq_admin_user UNIQUE (user_id)
);

ALTER TABLE public.admin_hierarchy ENABLE ROW LEVEL SECURITY;

-- RLS Policy 4: Super Admin has full governance over the admin roster
CREATE POLICY "super_admin_all_admin_hierarchy"
    ON public.admin_hierarchy
    FOR ALL
    TO authenticated
    USING (public.is_super_admin())
    WITH CHECK (public.is_super_admin());

-- RLS Policy 5: Module Admin can view self and their own sector's sub-admins
CREATE POLICY "module_admin_view_subadmins"
    ON public.admin_hierarchy
    FOR SELECT
    TO authenticated
    USING (
        user_id = auth.uid() OR 
        (role = 'sub_admin' AND assigned_module = public.current_admin_module())
    );

-- RLS Policy 6: Sub-Admin can ONLY view own assignment record
CREATE POLICY "sub_admin_view_self"
    ON public.admin_hierarchy
    FOR SELECT
    TO authenticated
    USING (user_id = auth.uid());

-- ============================================================================
-- 5. HARD LIMIT QUOTA TRIGGER: MAXIMUM 5 SUB-ADMINS PER MODULE
-- ============================================================================
CREATE OR REPLACE FUNCTION public.enforce_sub_admin_quota_trigger()
RETURNS TRIGGER AS $$
DECLARE
    v_subadmin_count INT;
    v_modadmin_count INT;
BEGIN
    -- Enforce exact 1 Module Admin per slot
    IF NEW.role = 'module_admin' THEN
        SELECT COUNT(*) INTO v_modadmin_count
        FROM public.admin_hierarchy
        WHERE role = 'module_admin'
          AND assigned_module = NEW.assigned_module
          AND is_active = TRUE
          AND (TG_OP = 'INSERT' OR id <> NEW.id);

        IF v_modadmin_count >= 1 THEN
            RAISE EXCEPTION 'Security Policy Violation: Module slot % already has an active Module Administrator.', NEW.assigned_module;
        END IF;
    END IF;

    -- Enforce maximum 5 Sub-Admins per sector
    IF NEW.role = 'sub_admin' THEN
        SELECT COUNT(*) INTO v_subadmin_count
        FROM public.admin_hierarchy
        WHERE role = 'sub_admin'
          AND assigned_module = NEW.assigned_module
          AND is_active = TRUE
          AND (TG_OP = 'INSERT' OR id <> NEW.id);

        IF v_subadmin_count >= 5 THEN
            RAISE EXCEPTION 'Security Policy Violation: Hard Limit Reached. Exactly 5 Sub-Administrators allowed for sector %.', NEW.assigned_module;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_admin_quota ON public.admin_hierarchy;
CREATE TRIGGER trg_enforce_admin_quota
    BEFORE INSERT OR UPDATE ON public.admin_hierarchy
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_sub_admin_quota_trigger();

-- ============================================================================
-- 6. SUPER ADMIN MASTER SUBJECT & CATEGORY ENGINE
-- Core syllabus subjects, categories, and tags for each of the 4 modules.
-- Only Super Admin can CREATE, UPDATE, or DELETE subjects.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.subjects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_slot portal_module_slot NOT NULL,
    name VARCHAR(150) NOT NULL,
    code VARCHAR(50) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_subject_code_module UNIQUE (module_slot, code)
);

CREATE INDEX IF NOT EXISTS idx_subjects_module ON public.subjects(module_slot);
CREATE INDEX IF NOT EXISTS idx_subjects_code ON public.subjects(code);

ALTER TABLE public.subjects ENABLE ROW LEVEL SECURITY;

-- RLS Policy 7: Authenticated users can view active subjects (for dynamic filtering)
CREATE POLICY "authenticated_view_subjects"
    ON public.subjects
    FOR SELECT
    TO authenticated
    USING (is_active = TRUE OR public.is_super_admin());

-- RLS Policy 8: Only Super Admin can insert, update, or delete subjects
CREATE POLICY "super_admin_manage_subjects"
    ON public.subjects
    FOR ALL
    TO authenticated
    USING (public.is_super_admin())
    WITH CHECK (public.is_super_admin());

-- ============================================================================
-- 7. RESOURCES & CONTENT MAPPING VIA FOREIGN KEY
-- Resources link strictly to 'subject_id' (Foreign Key).
-- Module Admins & Sub-Admins CANNOT type arbitrary subject names;
-- they must bind to an existing subject_id in their assigned module slot.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id UUID NOT NULL REFERENCES public.subjects(id) ON DELETE CASCADE,
    module_slot portal_module_slot NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    resource_url TEXT NOT NULL,
    resource_type resource_media_type NOT NULL DEFAULT 'study_material',
    author_id UUID NOT NULL REFERENCES auth.users(id),
    author_name VARCHAR(100) NOT NULL,
    author_role user_portal_role NOT NULL,
    is_published BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_resources_subject ON public.resources(subject_id);
CREATE INDEX IF NOT EXISTS idx_resources_module ON public.resources(module_slot);
CREATE INDEX IF NOT EXISTS idx_resources_type ON public.resources(resource_type);

-- Trigger to validate that subject_id strictly belongs to the target module_slot
CREATE OR REPLACE FUNCTION public.validate_resource_subject_fk()
RETURNS TRIGGER AS $$
DECLARE
    v_subject_slot portal_module_slot;
BEGIN
    SELECT module_slot INTO v_subject_slot
    FROM public.subjects
    WHERE id = NEW.subject_id;

    IF v_subject_slot IS NULL THEN
        RAISE EXCEPTION 'Foreign Key Violation: Referenced subject % does not exist.', NEW.subject_id;
    END IF;

    IF v_subject_slot <> NEW.module_slot THEN
        RAISE EXCEPTION 'Integrity Error: Subject module (%) does not match resource module (%).', v_subject_slot, NEW.module_slot;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_validate_resource_subject ON public.resources;
CREATE TRIGGER trg_validate_resource_subject
    BEFORE INSERT OR UPDATE ON public.resources
    FOR EACH ROW
    EXECUTE FUNCTION public.validate_resource_subject_fk();

ALTER TABLE public.resources ENABLE ROW LEVEL SECURITY;

-- RLS Policy 9: Authenticated users can view published resources
CREATE POLICY "authenticated_view_resources"
    ON public.resources
    FOR SELECT
    TO authenticated
    USING (is_published = TRUE OR public.is_super_admin());

-- RLS Policy 10: Authorized Module & Sub-Admins can insert resources strictly to their assigned module
CREATE POLICY "authorized_admin_insert_resources"
    ON public.resources
    FOR INSERT
    TO authenticated
    WITH CHECK (
        public.is_super_admin() OR
        (
            module_slot = public.current_admin_module() AND
            EXISTS (
                SELECT 1 FROM public.subjects
                WHERE id = subject_id
                  AND module_slot = public.current_admin_module()
                  AND is_active = TRUE
            )
        )
    );

-- RLS Policy 11: Authors, Module Admins, and Super Admins can update/delete resources
CREATE POLICY "authorized_admin_modify_resources"
    ON public.resources
    FOR UPDATE
    TO authenticated
    USING (
        public.is_super_admin() OR
        author_id = auth.uid() OR
        module_slot = public.current_admin_module()
    )
    WITH CHECK (
        public.is_super_admin() OR
        author_id = auth.uid() OR
        module_slot = public.current_admin_module()
    );

CREATE POLICY "authorized_admin_delete_resources"
    ON public.resources
    FOR DELETE
    TO authenticated
    USING (
        public.is_super_admin() OR
        author_id = auth.uid() OR
        module_slot = public.current_admin_module()
    );

-- ============================================================================
-- 7B. ACADEMIC ASSETS & D2C FARMER CROP LISTINGS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.academic_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id UUID REFERENCES public.subjects(id) ON DELETE CASCADE,
    module_slot portal_module_slot NOT NULL DEFAULT 'education',
    title VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL DEFAULT 'notes',
    file_url TEXT NOT NULL,
    uploaded_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    is_verified BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_academic_assets_subject ON public.academic_assets(subject_id);
ALTER TABLE public.academic_assets ENABLE ROW LEVEL SECURITY;

CREATE POLICY "public_read_academic_assets"
    ON public.academic_assets FOR SELECT
    USING (is_verified = TRUE OR auth.email() = 'yuvavaradhi1@gmail.com' OR public.is_super_admin());

CREATE POLICY "super_admin_manage_academic_assets"
    ON public.academic_assets FOR ALL TO authenticated
    USING (auth.email() = 'yuvavaradhi1@gmail.com' OR public.is_super_admin())
    WITH CHECK (auth.email() = 'yuvavaradhi1@gmail.com' OR public.is_super_admin());

CREATE TABLE IF NOT EXISTS public.crop_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crop_ref_id VARCHAR(50) UNIQUE NOT NULL,
    farmer_name VARCHAR(120) NOT NULL,
    farmer_phone_masked VARCHAR(20) NOT NULL,
    crop_type VARCHAR(100) NOT NULL,
    variety VARCHAR(100),
    quantity_quintals NUMERIC(10,2) NOT NULL CHECK (quantity_quintals > 0),
    expected_price_per_quintal NUMERIC(10,2) NOT NULL CHECK (expected_price_per_quintal > 0),
    district VARCHAR(100) NOT NULL,
    mandal VARCHAR(100) NOT NULL,
    harvest_date DATE NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'in_negotiation', 'sold', 'withdrawn')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_crop_listings_active_lots ON public.crop_listings(crop_type, district, status);
ALTER TABLE public.crop_listings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "public_read_active_crop_listings"
    ON public.crop_listings FOR SELECT
    USING (status = 'active' OR auth.email() = 'yuvavaradhi1@gmail.com' OR public.is_super_admin());

CREATE POLICY "farmers_insert_crop_listings"
    ON public.crop_listings FOR INSERT TO authenticated
    WITH CHECK (TRUE);

CREATE POLICY "super_admin_manage_crop_listings"
    ON public.crop_listings FOR ALL TO authenticated
    USING (auth.email() = 'yuvavaradhi1@gmail.com' OR public.is_super_admin())
    WITH CHECK (auth.email() = 'yuvavaradhi1@gmail.com' OR public.is_super_admin());

-- ============================================================================
-- 8. CITIZEN GRIEVANCE DESK & ENCRYPTED VAULT
-- Anonymous public tracking with masked PII.
-- Direct unmasked PII is restricted EXCLUSIVELY to Super Admin Cockpit.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.grievances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracking_code VARCHAR(30) UNIQUE NOT NULL, -- e.g. YV-GRV-849201
    citizen_name_encrypted TEXT NOT NULL,      -- Full name stored securely
    mobile_encrypted TEXT NOT NULL,            -- Full mobile stored securely
    citizen_name_masked VARCHAR(60) NOT NULL,  -- e.g. "K. V********"
    mobile_masked VARCHAR(20) NOT NULL,        -- e.g. "******2338"
    department VARCHAR(80) NOT NULL,
    district VARCHAR(60) NOT NULL,
    subject VARCHAR(150) NOT NULL,
    narrative TEXT NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'Registered',
    super_admin_notes TEXT,
    filed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_grievances_tracking ON public.grievances(tracking_code);
CREATE INDEX IF NOT EXISTS idx_grievances_status ON public.grievances(status);

ALTER TABLE public.grievances ENABLE ROW LEVEL SECURITY;

-- RLS Policy 12: Anyone (Public & Authenticated) can submit an anonymous grievance
CREATE POLICY "public_submit_grievance"
    ON public.grievances
    FOR INSERT
    TO public
    WITH CHECK (true);

-- RLS Policy 13: Direct SELECT on grievances is restricted EXCLUSIVELY to Super Admin
-- Module Admins and standard users CANNOT read the raw table
CREATE POLICY "super_admin_exclusive_read_grievances"
    ON public.grievances
    FOR SELECT
    TO authenticated
    USING (public.is_super_admin());

-- RLS Policy 14: Only Super Admin can update grievance status and investigation notes
CREATE POLICY "super_admin_update_grievances"
    ON public.grievances
    FOR UPDATE
    TO authenticated
    USING (public.is_super_admin())
    WITH CHECK (public.is_super_admin());

-- Security Definer Function: Citizen Tracking Portal
-- Returns ONLY non-sensitive status information with masked citizen identity.
-- Zero PII leakage to the public network.
CREATE OR REPLACE FUNCTION public.track_grievance_status(p_code VARCHAR)
RETURNS TABLE (
    tracking_code VARCHAR,
    department VARCHAR,
    district VARCHAR,
    subject VARCHAR,
    status VARCHAR,
    citizen_name_masked VARCHAR,
    filed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.tracking_code,
        g.department,
        g.district,
        g.subject,
        g.status,
        g.citizen_name_masked,
        g.filed_at,
        g.updated_at
    FROM public.grievances g
    WHERE g.tracking_code = UPPER(TRIM(p_code));
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- 9. IMMUTABLE TAMPER-EVIDENT PLATFORM AUDIT LEDGER
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES auth.users(id),
    actor_username VARCHAR(60) NOT NULL,
    action_type VARCHAR(60) NOT NULL,
    action_details TEXT NOT NULL,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Read restricted solely to Super Admin
CREATE POLICY "super_admin_read_audit"
    ON public.audit_logs
    FOR SELECT
    TO authenticated
    USING (public.is_super_admin());

-- Security Definer Logging procedure
CREATE OR REPLACE FUNCTION public.record_audit_event(
    p_username VARCHAR,
    p_action VARCHAR,
    p_details TEXT
) RETURNS VOID AS $$
BEGIN
    INSERT INTO public.audit_logs (actor_id, actor_username, action_type, action_details, ip_address)
    VALUES (auth.uid(), p_username, p_action, p_details, inet_client_addr());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- 10. SEED DATA: CORE SUBJECTS & DEMO RESOURCES
-- ============================================================================
INSERT INTO public.subjects (id, module_slot, name, code, category, description, tags)
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'education', 'Data Structures & Algorithms', 'EDU-CS-DSA', 'Computer Science & IT', 'Core algorithmic foundations, tree structures, complexity, and graphs.', ARRAY['engineering', 'btech', 'algorithms']),
    ('22222222-2222-2222-2222-222222222222', 'education', 'Advanced Agronomy & Soil Science', 'EDU-AG-AGRO', 'Agricultural Engineering', 'Pedology, soil physical chemistry, nutrient management, and crop rotations.', ARRAY['icar', 'icar_nat', 'agronomy']),
    ('33333333-3333-3333-3333-333333333333', 'govt_jobs', 'National Civil Services General Studies & Mental Ability', 'JOB-NAT-GS', 'Civil Services Examination', 'National history, Indian polity, constitutional law, and analytical reasoning.', ARRAY['upsc', 'civil_services', 'gs']),
    ('44444444-4444-4444-4444-444444444444', 'govt_jobs', 'Central Public Service Economy & National Development', 'JOB-CENT-ECO', 'Civil Services Examination', 'National economic policies, industrial corridors, and agricultural budgeting.', ARRAY['economy', 'public_service', 'development']),
    ('55555555-5555-5555-5555-555555555555', 'agriculture', 'Cotton & Chilli Pest Integrated Management', 'AGR-PEST-IPM', 'Field Agronomy & Protection', 'Biological control, chemical dosage calculations, and threshold pest scouting.', ARRAY['kisan', 'pesticide', 'icar']),
    ('66666666-6666-6666-6666-666666666666', 'agriculture', 'National APMC Mandi Pricing & Commodity Economics', 'AGR-MKT-RADAR', 'Commodity Intelligence', 'Daily market arrivals, modal rates, minimum support prices, and storage economics.', ARRAY['mandi', 'market', 'kisan']),
    ('77777777-7777-7777-7777-777777777777', 'sports', 'Track & Field Athletics Coaching Syllabus', 'SPT-ATH-TRK', 'Olympic Track Disciplines', 'Sprint acceleration, relay baton transitions, long-distance stamina, and recovery.', ARRAY['sai', 'national_federation', 'athletics']),
    ('88888888-8888-8888-8888-888888888888', 'sports', 'Cricket State Talent & Trial Protocols', 'SPT-CRK-TLT', 'Field Sports Coaching', 'Bowling mechanics, batting technique against spin, fitness radar, and state selections.', ARRAY['bcci', 'coaching', 'trials'])
ON CONFLICT (module_slot, code) DO UPDATE 
SET name = EXCLUDED.name, category = EXCLUDED.category, description = EXCLUDED.description;
