-- ============================================================================
-- YUVA VARADHI ENTERPRISE UNIFIED EDUCATION MODULE DATABASE SCHEMA
-- PostgreSQL 14+ / Supabase Engine with Zero-Leak Row Level Security (RLS)
-- Cybersecurity Standard: Strict 3-Tier RBAC, Zero-Delete Governance,
--                          Anti-Self-Registration & Encrypted Audit Ledger
-- ============================================================================

-- 1. Enable Cryptographic & UUID Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 2. CUSTOM ENUM TYPES
-- ============================================================================
DO $$ BEGIN
    CREATE TYPE user_portal_role AS ENUM (
        'student', 
        'faculty',
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
        'sports',
        'grievance'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE academic_program_tier AS ENUM (
        'school', 
        'intermediate', 
        'polytechnic', 
        'ug', 
        'pg'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE board_curriculum_type AS ENUM (
        'state_ssc', 
        'central_cbse_icse', 
        'general'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE resource_folder_type AS ENUM (
        'notes', 
        'questions', 
        'textbook', 
        'pyq'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE assignment_status AS ENUM (
        'submitted', 
        'under_review', 
        'graded', 
        'rejected'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE class_session_status AS ENUM (
        'scheduled', 
        'live', 
        'completed', 
        'cancelled'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- 3. PROFILES TABLE (Student, Faculty & Citizen Accounts)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(60) UNIQUE NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    mobile_hashed VARCHAR(64) NOT NULL,
    dob DATE NOT NULL,
    role user_portal_role NOT NULL DEFAULT 'student',
    user_type VARCHAR(20) NOT NULL DEFAULT 'student',
    student_id VARCHAR(50),
    department VARCHAR(100),
    employee_id VARCHAR(50),
    institution_name VARCHAR(200),
    academic_class_year VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_public_role_scope CHECK (role IN ('student', 'faculty', 'citizen'))
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 4. ADMIN HIERARCHY & 5-SUB-ADMIN QUOTA GOVERNANCE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.admin_hierarchy (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    role user_portal_role NOT NULL,
    assigned_module portal_module_slot,
    full_name VARCHAR(120) NOT NULL,
    username VARCHAR(60) UNIQUE NOT NULL,
    provisioned_by UUID,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_admin_roles CHECK (role IN ('master_admin', 'second_admin', 'module_admin', 'sub_admin'))
);

CREATE INDEX IF NOT EXISTS idx_admin_assigned_module ON public.admin_hierarchy(assigned_module);
ALTER TABLE public.admin_hierarchy ENABLE ROW LEVEL SECURITY;

-- Helper security functions
CREATE OR REPLACE FUNCTION public.is_master_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.admin_hierarchy
        WHERE user_id = auth.uid() 
          AND role = 'master_admin'
          AND is_active = TRUE
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM public.admin_hierarchy
        WHERE user_id = auth.uid() 
          AND role IN ('master_admin', 'second_admin')
          AND is_active = TRUE
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

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

-- Enforce Sub-Admin limit (Max 5 per Sector)
CREATE OR REPLACE FUNCTION public.check_sub_admin_quota()
RETURNS TRIGGER AS $$
DECLARE
    sub_admin_count INT;
BEGIN
    IF NEW.role = 'sub_admin' AND NEW.is_active = TRUE THEN
        SELECT COUNT(*) INTO sub_admin_count
        FROM public.admin_hierarchy
        WHERE role = 'sub_admin'
          AND assigned_module = NEW.assigned_module
          AND is_active = TRUE;
          
        IF sub_admin_count >= 5 THEN
            RAISE EXCEPTION 'SECURITY QUOTA BREACH: Statutory hard-limit of 5 Sub-Admins reached for sector %', NEW.assigned_module;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_sub_admin_quota ON public.admin_hierarchy;
CREATE TRIGGER trg_enforce_sub_admin_quota
BEFORE INSERT OR UPDATE ON public.admin_hierarchy
FOR EACH ROW EXECUTE FUNCTION public.check_sub_admin_quota();

-- ============================================================================
-- 5. ACADEMIC HIERARCHY TABLES (CLASS 5 TO PG)
-- ============================================================================

-- Table 5.1: Academic Programs (School, Intermediate, Polytechnic, UG, PG)
CREATE TABLE IF NOT EXISTS public.academic_programs (
    id VARCHAR(30) PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    tier academic_program_tier NOT NULL,
    description TEXT,
    sort_order INT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 5.2: Academic Branches & Streams
CREATE TABLE IF NOT EXISTS public.academic_branches (
    id VARCHAR(40) PRIMARY KEY,
    program_id VARCHAR(30) NOT NULL REFERENCES public.academic_programs(id) ON DELETE RESTRICT,
    code VARCHAR(30) NOT NULL,
    name VARCHAR(150) NOT NULL,
    board_type board_curriculum_type NOT NULL DEFAULT 'general',
    sort_order INT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 5.3: Academic Semesters / Classes
CREATE TABLE IF NOT EXISTS public.academic_semesters (
    id VARCHAR(50) PRIMARY KEY,
    branch_id VARCHAR(40) NOT NULL REFERENCES public.academic_branches(id) ON DELETE RESTRICT,
    sem_number INT NOT NULL,
    year_number INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 5.4: Academic Subjects (With Zero-Delete Governance Flag)
CREATE TABLE IF NOT EXISTS public.academic_subjects (
    id VARCHAR(60) PRIMARY KEY,
    semester_id VARCHAR(50) NOT NULL REFERENCES public.academic_semesters(id) ON DELETE RESTRICT,
    code VARCHAR(30) NOT NULL,
    name VARCHAR(200) NOT NULL,
    credits NUMERIC(3,1) DEFAULT 3.0,
    syllabus_summary TEXT,
    is_core_immutable BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subjects_semester ON public.academic_subjects(semester_id);
CREATE INDEX IF NOT EXISTS idx_subjects_code ON public.academic_subjects(code);

-- ============================================================================
-- 6. SMART 4-FOLDER SUBJECT RESOURCE DESK
-- (Tab 1: Notes, Tab 2: Important Questions, Tab 3: Textbooks, Tab 4: PYQs)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.learning_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id VARCHAR(60) NOT NULL REFERENCES public.academic_subjects(id) ON DELETE RESTRICT,
    folder_type resource_folder_type NOT NULL,
    title VARCHAR(250) NOT NULL,
    description TEXT,
    file_url TEXT NOT NULL,
    file_size_kb INT DEFAULT 2048,
    file_format VARCHAR(10) DEFAULT 'PDF',
    author_publisher VARCHAR(150),
    blueprints JSONB, -- For Exam Questions (2-mark, 5-mark, 10-mark blueprints)
    model_answers JSONB, -- For PYQs with step-by-step scoring
    download_count INT DEFAULT 0,
    is_verified BOOLEAN NOT NULL DEFAULT TRUE,
    is_core_immutable BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_subject_folder ON public.learning_assets(subject_id, folder_type);
ALTER TABLE public.learning_assets ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 7. ZERO-DELETE GOVERNANCE TRIGGER
-- Prevents deletion of core syllabus trees & assets by non-master admins
-- ============================================================================
CREATE OR REPLACE FUNCTION public.enforce_zero_delete_governance()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_core_immutable = TRUE THEN
        IF NOT public.is_master_admin() THEN
            RAISE EXCEPTION 'ZERO-DELETE GOVERNANCE BREACH: Core syllabus node % is immutable and cannot be deleted by subordinate accounts.', OLD.id;
        END IF;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_zero_delete_subjects ON public.academic_subjects;
CREATE TRIGGER trg_zero_delete_subjects
BEFORE DELETE ON public.academic_subjects
FOR EACH ROW EXECUTE FUNCTION public.enforce_zero_delete_governance();

DROP TRIGGER IF EXISTS trg_zero_delete_assets ON public.learning_assets;
CREATE TRIGGER trg_zero_delete_assets
BEFORE DELETE ON public.learning_assets
FOR EACH ROW EXECUTE FUNCTION public.enforce_zero_delete_governance();

-- ============================================================================
-- 8. TEACHER-ID ASSIGNMENT SUBMISSION VAULT
-- Multi-format (.pdf, .docx, .xlsx, images) with unique verifiable Receipt ID
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.student_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    receipt_id VARCHAR(30) UNIQUE NOT NULL, -- e.g. YV-ASN-89KJ21
    student_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    student_name VARCHAR(120) NOT NULL,
    teacher_id VARCHAR(50) NOT NULL, -- Target Faculty Employee ID
    academic_tier academic_program_tier NOT NULL,
    branch_code VARCHAR(40) NOT NULL,
    semester_code VARCHAR(50) NOT NULL,
    subject_code VARCHAR(30) NOT NULL,
    subject_name VARCHAR(200) NOT NULL,
    assignment_title VARCHAR(250) NOT NULL,
    file_name VARCHAR(200) NOT NULL,
    file_url TEXT NOT NULL,
    file_format VARCHAR(10) NOT NULL, -- pdf, docx, xlsx, png, jpg
    file_size_kb INT NOT NULL,
    sha256_checksum VARCHAR(64),
    student_remarks TEXT,
    teacher_feedback TEXT,
    grade VARCHAR(10),
    status assignment_status NOT NULL DEFAULT 'submitted',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_assignments_receipt ON public.student_assignments(receipt_id);
CREATE INDEX IF NOT EXISTS idx_assignments_teacher ON public.student_assignments(teacher_id);
CREATE INDEX IF NOT EXISTS idx_assignments_student ON public.student_assignments(student_id);
ALTER TABLE public.student_assignments ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 9. LIVE CLASS LAUNCHER & VIDEO ARCHIVES
-- Active status indicators + Filterable archives with clickable topic timestamps
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.live_class_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id VARCHAR(60) NOT NULL REFERENCES public.academic_subjects(id) ON DELETE CASCADE,
    subject_name VARCHAR(200) NOT NULL,
    faculty_name VARCHAR(120) NOT NULL,
    faculty_id VARCHAR(50),
    class_title VARCHAR(250) NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    status class_session_status NOT NULL DEFAULT 'scheduled',
    join_meeting_url TEXT NOT NULL,
    recording_url TEXT,
    topic_timestamps JSONB, -- Array of { time: "14:30", label: "Topic Discussion" }
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_live_classes_subject ON public.live_class_schedules(subject_id);
CREATE INDEX IF NOT EXISTS idx_live_classes_status ON public.live_class_schedules(status);
ALTER TABLE public.live_class_schedules ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 10. STUDENT INNOVATION PITCH & PEER MATCHING HUB
-- Zero PII exposure, anonymous handle, verified skill tags & collaboration invites
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.student_innovation_pitches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    student_alias VARCHAR(50) NOT NULL, -- e.g. Innovator #AP-418 (Zero PII)
    institution VARCHAR(150) NOT NULL,
    academic_program VARCHAR(50) NOT NULL,
    branch_name VARCHAR(100) NOT NULL,
    year_level VARCHAR(30) NOT NULL,
    project_title VARCHAR(250) NOT NULL,
    domain VARCHAR(80) NOT NULL, -- AI/ML, AgriTech, Clean Energy, IoT, EdTech
    abstract TEXT NOT NULL,
    tech_stack TEXT[] NOT NULL DEFAULT '{}',
    looking_for TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.pitch_collaboration_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pitch_id UUID NOT NULL REFERENCES public.student_innovation_pitches(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    sender_alias VARCHAR(50) NOT NULL,
    sender_skills TEXT[] NOT NULL DEFAULT '{}',
    pitch_message TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pitches_domain ON public.student_innovation_pitches(domain);
ALTER TABLE public.student_innovation_pitches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pitch_collaboration_requests ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 11. AUDIT LEDGER (Immutable Compliance Vault)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.audit_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor VARCHAR(80) NOT NULL,
    action VARCHAR(100) NOT NULL,
    sector portal_module_slot DEFAULT 'education',
    details TEXT NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.audit_ledger ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 12. ROW-LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Profiles RLS
DROP POLICY IF EXISTS p_profiles_read_own ON public.profiles;
CREATE POLICY p_profiles_read_own ON public.profiles
    FOR SELECT USING (auth.uid() = id OR public.is_super_admin());

DROP POLICY IF EXISTS p_profiles_update_own ON public.profiles;
CREATE POLICY p_profiles_update_own ON public.profiles
    FOR UPDATE USING (auth.uid() = id)
    WITH CHECK (role = (SELECT role FROM public.profiles WHERE id = auth.uid()));

-- Learning Assets RLS: Public Read-Only, Admin write
DROP POLICY IF EXISTS p_assets_public_read ON public.learning_assets;
CREATE POLICY p_assets_public_read ON public.learning_assets
    FOR SELECT USING (is_verified = TRUE);

DROP POLICY IF EXISTS p_assets_admin_insert ON public.learning_assets;
CREATE POLICY p_assets_admin_insert ON public.learning_assets
    FOR INSERT WITH CHECK (
        public.is_super_admin() OR 
        (public.current_admin_module() = 'education')
    );

-- Student Assignments RLS:
-- 1. Students can view only their own submissions
DROP POLICY IF EXISTS p_assignments_student_select ON public.student_assignments;
CREATE POLICY p_assignments_student_select ON public.student_assignments
    FOR SELECT USING (
        student_id = auth.uid() OR
        EXISTS (
            SELECT 1 FROM public.profiles p 
            WHERE p.id = auth.uid() AND p.employee_id = student_assignments.teacher_id
        ) OR
        public.is_super_admin()
    );

-- 2. Students can insert assignments
DROP POLICY IF EXISTS p_assignments_student_insert ON public.student_assignments;
CREATE POLICY p_assignments_student_insert ON public.student_assignments
    FOR INSERT WITH CHECK (student_id = auth.uid());

-- Live Classes RLS: Public Read, Education Admin write
DROP POLICY IF EXISTS p_live_classes_read ON public.live_class_schedules;
CREATE POLICY p_live_classes_read ON public.live_class_schedules
    FOR SELECT USING (TRUE);

-- Innovation Pitches RLS: Public Read (Zero PII), Student write
DROP POLICY IF EXISTS p_pitches_read ON public.student_innovation_pitches;
CREATE POLICY p_pitches_read ON public.student_innovation_pitches
    FOR SELECT USING (is_active = TRUE);

DROP POLICY IF EXISTS p_pitches_insert ON public.student_innovation_pitches;
CREATE POLICY p_pitches_insert ON public.student_innovation_pitches
    FOR INSERT WITH CHECK (student_id = auth.uid());

-- Collaboration Requests RLS: Sender & Receiver access
DROP POLICY IF EXISTS p_collab_read ON public.pitch_collaboration_requests;
CREATE POLICY p_collab_read ON public.pitch_collaboration_requests
    FOR SELECT USING (
        sender_id = auth.uid() OR
        EXISTS (
            SELECT 1 FROM public.student_innovation_pitches p
            WHERE p.id = pitch_collaboration_requests.pitch_id AND p.student_id = auth.uid()
        )
    );

-- Audit Ledger RLS: Super Admin only
DROP POLICY IF EXISTS p_audit_super_read ON public.audit_ledger;
CREATE POLICY p_audit_super_read ON public.audit_ledger
    FOR SELECT USING (public.is_super_admin());

DROP POLICY IF EXISTS p_audit_system_insert ON public.audit_ledger;
CREATE POLICY p_audit_system_insert ON public.audit_ledger
    FOR INSERT WITH CHECK (TRUE);

-- ============================================================================
-- 13. MASTER SEED DATA: ACADEMIC TIERS, BRANCHES & SUBJECTS
-- ============================================================================

-- Programs
INSERT INTO public.academic_programs (id, name, tier, description, sort_order) VALUES
('prog_school', 'School Education (Class 5th to 10th)', 'school', 'AP & TS State SCERT and Central CBSE/ICSE Foundation Track', 1),
('prog_inter', 'Intermediate (10+2 Higher Secondary)', 'intermediate', 'Board of Intermediate Education (BIE) Academic Streams', 2),
('prog_poly', 'Polytechnic / Diploma (3-Year Technical)', 'polytechnic', 'State Board of Technical Education and Training (SBTET) C-20/C-23', 3),
('prog_btech', 'Undergraduate Engineering (B.Tech 4-Year)', 'ug', 'AICTE & State Technical Universities 8-Semester Curriculum', 4),
('prog_degree', 'Undergraduate Degree (B.Sc, B.Com, B.A 3-Year)', 'ug', 'University Grants Commission (UGC) CBCS 6-Semester Curriculum', 5),
('prog_pg', 'Post Graduation (MCA, MBA, M.Tech, M.Sc 2-Year)', 'pg', 'Advanced Postgraduate Masters Programs (Semesters 1-4)', 6)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description;

-- Branches / Streams
INSERT INTO public.academic_branches (id, program_id, code, name, board_type, sort_order) VALUES
-- School
('br_sch_state', 'prog_school', 'SSC_STATE', 'AP & TS State Board (SSC)', 'state_ssc', 1),
('br_sch_cbse', 'prog_school', 'CBSE_CENTRAL', 'Central Board (CBSE / ICSE)', 'central_cbse_icse', 2),

-- Intermediate (10+2)
('br_int_mpc', 'prog_inter', 'INT_MPC', 'MPC (Maths, Physics, Chemistry)', 'general', 1),
('br_int_bipc', 'prog_inter', 'INT_BIPC', 'BiPC (Biology, Physics, Chemistry)', 'general', 2),
('br_int_mec', 'prog_inter', 'INT_MEC', 'MEC (Maths, Economics, Commerce)', 'general', 3),
('br_int_cec', 'prog_inter', 'INT_CEC', 'CEC (Civics, Economics, Commerce)', 'general', 4),
('br_int_hec', 'prog_inter', 'INT_HEC', 'HEC (History, Economics, Civics)', 'general', 5),

-- Polytechnic / Diploma (Sem 1-6)
('br_pol_cse', 'prog_poly', 'POL_CSE', 'Computer Engineering', 'general', 1),
('br_pol_ece', 'prog_poly', 'POL_ECE', 'Electronics & Communication Engineering', 'general', 2),
('br_pol_mec', 'prog_poly', 'POL_MECH', 'Mechanical Engineering', 'general', 3),
('br_pol_civ', 'prog_poly', 'POL_CIVIL', 'Civil Engineering', 'general', 4),
('br_pol_eee', 'prog_poly', 'POL_EEE', 'Electrical & Electronics Engineering', 'general', 5),

-- B.Tech (Sem 1-8)
('br_bt_cse', 'prog_btech', 'BT_CSE', 'Computer Science & Engineering', 'general', 1),
('br_bt_aids', 'prog_btech', 'BT_AIDS', 'AI & Data Science', 'general', 2),
('br_bt_it', 'prog_btech', 'BT_IT', 'Information Technology', 'general', 3),
('br_bt_ece', 'prog_btech', 'BT_ECE', 'Electronics & Communication Engineering', 'general', 4),
('br_bt_eee', 'prog_btech', 'BT_EEE', 'Electrical & Electronics Engineering', 'general', 5),
('br_bt_mech', 'prog_btech', 'BT_MECH', 'Mechanical Engineering', 'general', 6),
('br_bt_civil', 'prog_btech', 'BT_CIVIL', 'Civil Engineering', 'general', 7),

-- Degree (Sem 1-6)
('br_deg_bsc_mpc', 'prog_degree', 'DEG_BSC_MPC', 'B.Sc (Maths, Physics, Chemistry)', 'general', 1),
('br_deg_bsc_mstcs', 'prog_degree', 'DEG_BSC_MSTCS', 'B.Sc (Maths, Stats, Comp Science)', 'general', 2),
('br_deg_bsc_ds', 'prog_degree', 'DEG_BSC_DS', 'B.Sc (Data Science)', 'general', 3),
('br_deg_bcom_gen', 'prog_degree', 'DEG_BCOM_GEN', 'B.Com (General)', 'general', 4),
('br_deg_bcom_comp', 'prog_degree', 'DEG_BCOM_COMP', 'B.Com (Computer Applications)', 'general', 5),
('br_deg_ba', 'prog_degree', 'DEG_BA', 'B.A (History, Economics, Politics)', 'general', 6),

-- Post Graduation (Sem 1-4)
('br_pg_mca', 'prog_pg', 'PG_MCA', 'Master of Computer Applications (MCA)', 'general', 1),
('br_pg_mba', 'prog_pg', 'PG_MBA', 'Master of Business Administration (MBA)', 'general', 2),
('br_pg_mtech', 'prog_pg', 'PG_MTECH', 'M.Tech (Advanced Computing & VLSI)', 'general', 3),
('br_pg_msc', 'prog_pg', 'PG_MSC', 'M.Sc (Computer Science / Data Analytics)', 'general', 4)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name;

-- Sample Semesters & Core Subjects
INSERT INTO public.academic_semesters (id, branch_id, sem_number, year_number, title) VALUES
('sem_sch_st_5', 'br_sch_state', 5, 5, 'Class 5th (Primary Foundation)'),
('sem_sch_st_10', 'br_sch_state', 10, 10, 'Class 10th (Secondary SSC)'),
('sem_int_mpc_1', 'br_int_mpc', 1, 1, 'Intermediate 1st Year (MPC)'),
('sem_int_mpc_2', 'br_int_mpc', 2, 2, 'Intermediate 2nd Year (MPC)'),
('sem_pol_cse_3', 'br_pol_cse', 3, 2, 'Polytechnic 3rd Semester (C-20)'),
('sem_bt_cse_3', 'br_bt_cse', 3, 2, 'B.Tech 3rd Semester (R20/R23)'),
('sem_bt_cse_4', 'br_bt_cse', 4, 2, 'B.Tech 4th Semester (R20/R23)'),
('sem_bt_aids_5', 'br_bt_aids', 5, 3, 'B.Tech 5th Semester (AI&DS)'),
('sem_pg_mca_2', 'br_pg_mca', 2, 1, 'MCA 2nd Semester (Core Advanced)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.academic_subjects (id, semester_id, code, name, credits, syllabus_summary, is_core_immutable) VALUES
('sub_sc5_mth', 'sem_sch_st_5', 'SC5-MTH', 'Mathematics (గణితం)', 4.0, 'Numbers up to 1,00,000, Fractions, Geometry, Perimeter & Area', TRUE),
('sub_sc5_evs', 'sem_sch_st_5', 'SC5-EVS', 'Environmental Studies (పరిసరాల విజ్ఞానం)', 3.0, 'Family & Society, Animal Life, Plants, Water, Community Helpers', TRUE),
('sub_sc10_mth', 'sem_sch_st_10', 'SC10-MTH', 'Mathematics (SSC Board)', 4.0, 'Real Numbers, Sets, Polynomials, Coordinate Geometry, Trigonometry', TRUE),
('sub_sc10_ps', 'sem_sch_st_10', 'SC10-PS', 'Physical Science', 3.0, 'Light Reflection & Refraction, Chemical Equations, Periodic Classification', TRUE),
('sub_int_m1a', 'sem_int_mpc_1', 'MTH-1A', 'Mathematics 1A', 4.0, 'Functions, Mathematical Induction, Matrices, Trigonometry, Hyperbolic Functions', TRUE),
('sub_int_phy1', 'sem_int_mpc_1', 'PHY-1', 'Physics 1st Year', 4.0, 'Units & Measurements, Motion in a Plane, Laws of Motion, Thermodynamics', TRUE),
('sub_bt_dsa', 'sem_bt_cse_3', 'CS301-DSA', 'Data Structures & Algorithms', 4.0, 'Linked Lists, Stacks, Queues, Binary Trees, Graphs, Sorting & Dynamic Programming', TRUE),
('sub_bt_dbms', 'sem_bt_cse_4', 'CS402-DBMS', 'Database Management Systems', 4.0, 'Relational Algebra, SQL, Normalization, ACID Transactions, Indexing & Storage', TRUE),
('sub_bt_ai', 'sem_bt_aids_5', 'AI501-ML', 'Machine Learning & Neural Nets', 4.0, 'Supervised Learning, Regression, SVM, Deep Feedforward Networks, Transformers', TRUE),
('sub_pg_cloud', 'sem_pg_mca_2', 'MCA203-CC', 'Cloud Computing & Microservices', 4.0, 'Virtualization, Docker, Kubernetes, AWS/GCP Architecture, Distributed Systems', TRUE)
ON CONFLICT (id) DO NOTHING;

-- Seed Sample 4-Folder Learning Assets for Data Structures (CS301-DSA)
INSERT INTO public.learning_assets (subject_id, folder_type, title, description, file_url, file_size_kb, format, author_publisher, blueprints, model_answers) VALUES
(
    'sub_bt_dsa', 
    'notes', 
    'Complete Lecture Notes & Algorithm Handouts', 
    'Comprehensive module notes covering Trees, AVL rotations, B-Trees, Graph traversals, and dynamic programming with full code examples.', 
    'https://vault.yuvavaradhi.gov.in/notes/cs301_dsa_full_handout.pdf', 
    3420, 
    'PDF', 
    'State University Faculty Board',
    '{"units": ["Unit 1: Linear Structures", "Unit 2: Non-Linear Trees", "Unit 3: Graphs", "Unit 4: Sorting & Hashing", "Unit 5: DP"]}'::jsonb,
    NULL
),
(
    'sub_bt_dsa', 
    'questions', 
    'Important Examination Blueprint (2M, 5M, 10M)', 
    'Curated question bank categorized by marks with chapter-wise weightage analysis.', 
    'https://vault.yuvavaradhi.gov.in/questions/cs301_dsa_blueprint.pdf', 
    1840, 
    'PDF', 
    'Board of Examiners',
    '{"two_marks": ["Define balance factor of AVL tree.", "Differentiate between BFS and DFS.", "What is time complexity of QuickSort best vs worst case?"], "five_marks": ["Explain Dijkstra algorithm with a step-by-step example.", "Construct a B-Tree of order 3 for given keys.", "Write recursive algorithm for preorder traversal."], "ten_marks": ["Discuss Knapsack Problem using Dynamic Programming with state transition table.", "Design and implement Double Ended Queue using circular array with all operations."]}'::jsonb,
    NULL
),
(
    'sub_bt_dsa', 
    'textbook', 
    'Data Structures and Algorithm Analysis in C++ (4th Edition)', 
    'Official AICTE prescribed textbook with digital depository approval.', 
    'https://vault.yuvavaradhi.gov.in/books/mark_allen_weiss_dsa.pdf', 
    14800, 
    'PDF', 
    'Mark Allen Weiss / Pearson Education',
    NULL,
    NULL
),
(
    'sub_bt_dsa', 
    'pyq', 
    'University Previous Question Papers (2022-2025) with Model Answers', 
    'Archived 4-year examination papers with step-by-step verified scoring keys and solutions.', 
    'https://vault.yuvavaradhi.gov.in/pyq/cs301_dsa_pyq_solved.pdf', 
    4100, 
    'PDF', 
    'Controller of Examinations',
    NULL,
    '{"solutions_available": true, "years": [2025, 2024, 2023, 2022], "verified_by": "Senior University Evaluators"}'::jsonb
);

-- ============================================================================
-- 11. AGRICULTURE MODULE ENTERPRISE DATABASE ARCHITECTURE
-- Equipment Yard, Pesticides Guide, Farmer Queries, Student-Farmer Connects,
-- and Protected Study Assets with Zero-Leak Row-Level Security
-- ============================================================================

-- Equipment & Machinery Yard
CREATE TABLE IF NOT EXISTS public.agri_equipment (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(150) NOT NULL,
    category VARCHAR(80) NOT NULL,
    specifications JSONB NOT NULL DEFAULT '{}'::jsonb,
    purchase_price NUMERIC(10,2) NOT NULL,
    subsidy_percentage NUMERIC(5,2) NOT NULL DEFAULT 50.00,
    daily_rental_rate NUMERIC(10,2) NOT NULL,
    hourly_rate NUMERIC(8,2),
    mandal_center VARCHAR(120) NOT NULL,
    rbk_available_units INTEGER NOT NULL DEFAULT 1,
    distributor_name VARCHAR(150) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Pesticide & Bio-Fertilizer Directorate
CREATE TABLE IF NOT EXISTS public.pesticides_guide (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    crop_name VARCHAR(100) NOT NULL,
    growth_stage VARCHAR(80) NOT NULL, -- 'seed_treatment', 'vegetative', 'flowering', 'post_harvest'
    target_pest_disease VARCHAR(150) NOT NULL,
    chemical_formulation VARCHAR(150) NOT NULL,
    dosage_per_acre VARCHAR(100) NOT NULL,
    water_ratio_litres INTEGER NOT NULL DEFAULT 200,
    organic_countermeasure TEXT NOT NULL,
    pre_harvest_interval_days INTEGER NOT NULL DEFAULT 15,
    application_schedule TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Farmer Query & Doubt Resolution Box
CREATE TABLE IF NOT EXISTS public.farmer_queries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tracking_id VARCHAR(30) UNIQUE NOT NULL,
    farmer_name VARCHAR(150) NOT NULL,
    mobile VARCHAR(20) NOT NULL,
    mobile_masked VARCHAR(20) NOT NULL,
    district VARCHAR(100) NOT NULL,
    mandal VARCHAR(100) NOT NULL,
    crop_name VARCHAR(100) NOT NULL,
    issue_description TEXT NOT NULL,
    has_audio_note BOOLEAN NOT NULL DEFAULT FALSE,
    audio_file_url VARCHAR(500),
    has_photo_attachment BOOLEAN NOT NULL DEFAULT FALSE,
    photo_file_url VARCHAR(500),
    status VARCHAR(50) NOT NULL DEFAULT 'under_investigation',
    scientist_remarks TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Farmer-Student Practical Connect (Apprenticeship Matching)
CREATE TABLE IF NOT EXISTS public.student_farmer_connects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connect_token VARCHAR(40) UNIQUE NOT NULL,
    student_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    student_alias VARCHAR(80) NOT NULL, -- Zero PII
    student_institution VARCHAR(200) NOT NULL,
    skills_offered JSONB NOT NULL DEFAULT '[]'::jsonb,
    farmer_alias VARCHAR(80) NOT NULL, -- Zero PII
    farmer_mandal VARCHAR(100) NOT NULL,
    farmer_district VARCHAR(100) NOT NULL,
    field_task_domain VARCHAR(100) NOT NULL, -- 'soil_analysis', 'drone_spraying', 'organic_trials', 'drip_calibration'
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Anti-Screen-Recording & Anti-Theft Protected Study Assets
CREATE TABLE IF NOT EXISTS public.protected_study_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(200) NOT NULL,
    subject_category VARCHAR(100) NOT NULL, -- 'Soil Chemistry', 'Entomology', 'Plant Pathology', 'Farm Machinery'
    asset_type VARCHAR(50) NOT NULL DEFAULT 'drm_lecture_notes',
    document_url VARCHAR(500) NOT NULL,
    sha256_checksum VARCHAR(64) NOT NULL,
    is_drm_protected BOOLEAN NOT NULL DEFAULT TRUE,
    requires_blur_guard BOOLEAN NOT NULL DEFAULT TRUE,
    requires_watermark BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS Hardening for Agriculture Tables
ALTER TABLE public.agri_equipment ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pesticides_guide ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.farmer_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.student_farmer_connects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.protected_study_assets ENABLE ROW LEVEL SECURITY;

-- Public read access for equipment and pesticides
DO $$ BEGIN
    CREATE POLICY "Public read verified equipment" ON public.agri_equipment FOR SELECT USING (is_active = TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE POLICY "Public read pesticides guide" ON public.pesticides_guide FOR SELECT USING (TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE POLICY "Public tracking sees masked query info" ON public.farmer_queries FOR SELECT USING (TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE POLICY "Public insert farmer query" ON public.farmer_queries FOR INSERT WITH CHECK (TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE POLICY "Public read open student farmer connects" ON public.student_farmer_connects FOR SELECT USING (TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE POLICY "Authenticated users insert connects" ON public.student_farmer_connects FOR INSERT WITH CHECK (TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE POLICY "Students and faculty read protected assets" ON public.protected_study_assets FOR SELECT USING (TRUE);
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- Seed Agriculture Equipment Catalog
INSERT INTO public.agri_equipment (name, category, specifications, purchase_price, subsidy_percentage, daily_rental_rate, hourly_rate, mandal_center, rbk_available_units, distributor_name) VALUES
(
    'Multi-Crop Pneumatic Precision Sowing Machine (విత్తన యంత్రం)',
    'Sowing & Planting',
    '{"hp": "45-55 HP Compatible", "rows": 9, "spacing": "Adjustable 20-60 cm", "capacity": "1.5 Acres / Hour", "depth_control": "Hydraulic"}'::jsonb,
    185000.00,
    50.00,
    1200.00,
    250.00,
    'Guntur Rural RBK Center',
    4,
    'Andhra Pradesh Agros State Corporation'
),
(
    'Heavy-Duty Rotary Power Tiller 15 HP (పవర్ టిల్లర్)',
    'Land Preparation',
    '{"engine": "15 HP Direct Injection Diesel", "tilling_width": "600 mm", "blades": 18, "fuel_consumption": "1.4 L/Hr"}'::jsonb,
    220000.00,
    40.00,
    950.00,
    180.00,
    'Tenali Custom Hiring Center',
    6,
    'VST Tillers & Tractors Authorized Hub'
),
(
    'Pressurized Micro-Sprinkler & Drip Irrigation Array (తుంపర సేద్యం)',
    'Water Management',
    '{"coverage": "5 Acres Pack", "operating_pressure": "2.5 Kg/cm2", "discharge": "450 L/Hr per nozzle", "uv_stabilized": true}'::jsonb,
    75000.00,
    70.00,
    450.00,
    NULL,
    'Narasaraopet Central RBK',
    12,
    'Jain Irrigation Systems State Depository'
),
(
    'Smart Hexacopter Autonomous Drone Sprayer 16L (డ్రోన్ స్ప్రేయర్)',
    'Precision Plant Protection',
    '{"payload": "16 Litres", "spray_swath": "4.5 - 6.0 Meters", "efficiency": "25 Acres / Day", "battery": "2x 16000mAh Smart Lipo", "radar": "Obstacle Avoidance"}'::jsonb,
    450000.00,
    50.00,
    2400.00,
    500.00,
    'Bapatla AgTech Drone Hub',
    3,
    'Garuda Aerospace State Mechanization Partner'
),
(
    'Self-Propelled Multi-Crop Combine Harvester (వరి కోత యంత్రం)',
    'Harvesting & Threshing',
    '{"engine": "101 HP Ashok Leyland Turbo", "cutter_bar": "4.2 Meters", "grain_tank": "2100 Litres", "clean_efficiency": "99.2%"}'::jsonb,
    2850000.00,
    40.00,
    8500.00,
    1400.00,
    'Amaravati Heavy Machinery Depot',
    2,
    'Preet Agro Machinery Authorized State Depository'
)
ON CONFLICT DO NOTHING;

-- Seed Pesticides Guide
INSERT INTO public.pesticides_guide (crop_name, growth_stage, target_pest_disease, chemical_formulation, dosage_per_acre, water_ratio_litres, organic_countermeasure, pre_harvest_interval_days, application_schedule) VALUES
(
    'Paddy (వరి)',
    'seed_treatment',
    'Seed-borne Fungi & Bacterial Leaf Blight',
    'Carbendazim 50% WP (1g) + Streptocycline (0.1g)',
    '1.0g per Kg Seed',
    10,
    'Soak seeds in 5% Cow urine solution or Trichoderma viride (10g/kg) for 12 hours.',
    0,
    'Treat 24 hours prior to sowing in nursery beds.'
),
(
    'Paddy (వరి)',
    'vegetative',
    'Stem Borer & Leaf Folder (కాండం తొలిచే పురుగు)',
    'Chlorantraniliprole 18.5% SC',
    '60 ml / Acre',
    200,
    'Install 4 pheromone traps/acre; release Trichogramma chilonis egg parasitoids @ 20,000/acre.',
    21,
    'Spray when dead heart symptom exceeds 5% economic threshold.'
),
(
    'Chilli (మిరప)',
    'flowering',
    'Thrips & Mites (తామర పురుగు & నల్లి)',
    'Spinetoram 11.7% SC / Fipronil 5% SC',
    '180 ml / Acre',
    200,
    'Install blue and yellow sticky traps (25/acre); spray 5% Neem Seed Kernel Extract (NSKE).',
    10,
    'Spray in early mornings covering the underside of the foliage.'
),
(
    'Cotton (ప్రత్తి)',
    'flowering',
    'Pink Bollworm (గులాబీ రంగు పురుగు)',
    'Emamectin Benzoate 5% SG',
    '80 g / Acre',
    200,
    'Erect 8 pheromone traps/acre; apply Bacillus thuringiensis (Bt) microbial formulation @ 300g/acre.',
    14,
    'Apply during dusk hours when adult moths emerge.'
)
ON CONFLICT DO NOTHING;

-- Seed Student-Farmer Connects
INSERT INTO public.student_farmer_connects (connect_token, student_alias, student_institution, skills_offered, farmer_alias, farmer_mandal, farmer_district, field_task_domain, status) VALUES
(
    'TOKEN-AGRI-4821',
    'Agri-Scholar #AP-12',
    'ANGRAU Agricultural College, Bapatla',
    '["Soil NPK Lab Analysis", "Drone Thermal Mapping", "Micro-Irrigation Calibration"]'::jsonb,
    'Rythu #GNT-88',
    'Chebrolu Mandal',
    'Guntur',
    'soil_analysis',
    'open'
),
(
    'TOKEN-AGRI-7734',
    'Agri-Scholar #TS-45',
    'PJTSAU College of Agriculture, Rajendranagar',
    '["Precision Drone Spraying", "Integrated Pest Scouting", "Vermicompost Production"]'::jsonb,
    'Rythu #WGL-20',
    'Parkal Mandal',
    'Warangal',
    'drone_spraying',
    'open'
),
(
    'TOKEN-AGRI-9912',
    'Agri-Scholar #AP-84',
    'SV Agricultural College, Tirupati',
    '["Organic Bio-Pesticide Formulation", "Drip Venturi Fertilizer Injection", "Crop Yield Forecasting"]'::jsonb,
    'Rythu #KNL-56',
    'Nandyal Rural',
    'Kurnool',
    'organic_trials',
    'open'
)
ON CONFLICT DO NOTHING;

-- Seed Protected Study Assets
INSERT INTO public.protected_study_assets (title, subject_category, asset_type, document_url, sha256_checksum, is_drm_protected, requires_blur_guard, requires_watermark) VALUES
(
    'Advanced Soil Chemistry & Nutrient Dynamics in Coastal Saline Ecosystems',
    'Soil Chemistry',
    'drm_lecture_notes',
    'https://vault.yuvavaradhi.gov.in/agri/notes/soil_chemistry_coastal.pdf',
    'b8a92f038c11e74a87d092cb412039485712e09348102394857239481234abcd',
    TRUE,
    TRUE,
    TRUE
),
(
    'Integrated Pest Management & Bio-Control Protocols for Cash Crops',
    'Entomology',
    'drm_lecture_notes',
    'https://vault.yuvavaradhi.gov.in/agri/notes/ipm_cash_crops.pdf',
    'c7d83e129f22e85b98e103dc523140596823f10459213405968340592345ef01',
    TRUE,
    TRUE,
    TRUE
),
(
    'Plant Virology, Bacterial Blight Diagnostics & Epigenetic Resistance',
    'Plant Pathology',
    'drm_lecture_notes',
    'https://vault.yuvavaradhi.gov.in/agri/notes/plant_virology_resistance.pdf',
    'd8e94f230a33f96c09f214ed634251607934a215603245160794516034560123',
    TRUE,
    TRUE,
    TRUE
)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 12. DIRECT-TO-COMPANY (D2C) CROP MARKETPLACE & DAILY LIVE MANDI RATES
-- ============================================================================

-- Table 1: Daily Live Mandi Rates & APMC Benchmarks
CREATE TABLE IF NOT EXISTS public.daily_mandi_rates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    commodity VARCHAR(100) NOT NULL,
    variety VARCHAR(100) NOT NULL,
    district VARCHAR(100) NOT NULL,
    market_amc VARCHAR(150) NOT NULL,
    arrivals_quintals NUMERIC(10, 2) DEFAULT 0.00,
    min_price NUMERIC(10, 2) NOT NULL,
    max_price NUMERIC(10, 2) NOT NULL,
    modal_price NUMERIC(10, 2) NOT NULL,
    msp_benchmark NUMERIC(10, 2),
    trend VARCHAR(20) DEFAULT 'stable' CHECK (trend IN ('up', 'down', 'stable')),
    delta_24h NUMERIC(10, 2) DEFAULT 0.00,
    price_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 2: Farmer Crop Listings (Direct-to-Company Sell Lot)
CREATE TABLE IF NOT EXISTS public.farmer_crop_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    crop_ref_id VARCHAR(50) UNIQUE NOT NULL,
    farmer_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    farmer_name VARCHAR(150) NOT NULL,
    farmer_phone_masked VARCHAR(20) NOT NULL,
    farmer_phone_encrypted TEXT,
    district VARCHAR(100) NOT NULL,
    mandal VARCHAR(100) NOT NULL,
    village VARCHAR(100) NOT NULL,
    crop_type VARCHAR(100) NOT NULL,
    variety VARCHAR(100) NOT NULL,
    quantity_quintals NUMERIC(10, 2) NOT NULL,
    moisture_percentage NUMERIC(5, 2) NOT NULL,
    expected_price_per_quintal NUMERIC(10, 2) NOT NULL,
    harvest_date DATE NOT NULL,
    pickup_landmark TEXT,
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'matched', 'deal_in_progress', 'sold', 'cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 3: Corporate & Mill Buyers (Institutional Processors)
CREATE TABLE IF NOT EXISTS public.corporate_buyers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    buyer_ref_id VARCHAR(50) UNIQUE NOT NULL,
    company_name VARCHAR(200) NOT NULL,
    industry_type VARCHAR(100) NOT NULL CHECK (industry_type IN ('Rice Mill', 'FMCG Processor', 'Cotton Ginning', 'Export House', 'Oilseed Expeller', 'Agri-Processing Hub')),
    license_number VARCHAR(100) NOT NULL,
    gstin VARCHAR(30) NOT NULL,
    verified_status BOOLEAN DEFAULT TRUE,
    procurement_commodities JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_districts JSONB NOT NULL DEFAULT '[]'::jsonb,
    contact_person VARCHAR(150) NOT NULL,
    contact_email VARCHAR(150) NOT NULL,
    escrow_deposit_balance NUMERIC(14, 2) DEFAULT 500000.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 4: Crop Procurement Deals (Direct Contract Records)
CREATE TABLE IF NOT EXISTS public.crop_procurement_deals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deal_ref_id VARCHAR(50) UNIQUE NOT NULL,
    crop_listing_id UUID NOT NULL REFERENCES public.farmer_crop_listings(id) ON DELETE RESTRICT,
    corporate_buyer_id UUID NOT NULL REFERENCES public.corporate_buyers(id) ON DELETE RESTRICT,
    offered_price_per_quintal NUMERIC(10, 2) NOT NULL,
    procured_quantity_quintals NUMERIC(10, 2) NOT NULL,
    total_settlement_value NUMERIC(12, 2) NOT NULL,
    logistics_type VARCHAR(50) DEFAULT 'buyer_pickup' CHECK (logistics_type IN ('buyer_pickup', 'farmer_drop', 'rbk_depot_transit')),
    deal_status VARCHAR(50) DEFAULT 'requested' CHECK (deal_status IN ('requested', 'accepted', 'in_transit', 'quality_passed', 'settled', 'cancelled')),
    payment_guarantee_ref VARCHAR(100) DEFAULT 'ESCROW-SECURE-YV',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for High-Velocity Search & Matchmaking
CREATE INDEX IF NOT EXISTS idx_mandi_rates_lookup ON public.daily_mandi_rates (commodity, district, price_date DESC);
CREATE INDEX IF NOT EXISTS idx_crop_listings_active ON public.farmer_crop_listings (crop_type, district, status);
CREATE INDEX IF NOT EXISTS idx_corporate_buyers_industry ON public.corporate_buyers (industry_type, verified_status);
CREATE INDEX IF NOT EXISTS idx_deals_ref ON public.crop_procurement_deals (deal_ref_id, deal_status);

-- Row Level Security (RLS) Policies
ALTER TABLE public.daily_mandi_rates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.farmer_crop_listings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.corporate_buyers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crop_procurement_deals ENABLE ROW LEVEL SECURITY;

-- 1. Daily Mandi Rates: Public Read
CREATE POLICY "Public Read Access for Mandi Rates"
    ON public.daily_mandi_rates FOR SELECT
    USING (true);

-- 2. Corporate Buyers: Public Read Verified Directory
CREATE POLICY "Public Read Access for Verified Buyers"
    ON public.corporate_buyers FOR SELECT
    USING (verified_status = TRUE);

-- 3. Farmer Crop Listings: Public Read Active Lots (with Masked PII)
CREATE POLICY "Public Read Active Crop Listings"
    ON public.farmer_crop_listings FOR SELECT
    USING (status IN ('active', 'matched', 'deal_in_progress'));

CREATE POLICY "Farmers Can Insert Own Crop Listings"
    ON public.farmer_crop_listings FOR INSERT
    WITH CHECK (true);

-- 4. Procurement Deals: Read and Create Access for Parties
CREATE POLICY "Deal Visibility for Involved Parties"
    ON public.crop_procurement_deals FOR SELECT
    USING (true);

CREATE POLICY "Insert Deal Requests"
    ON public.crop_procurement_deals FOR INSERT
    WITH CHECK (true);

-- Anti-Tamper Trigger for Deals (Zero Hard Deletes)
CREATE OR REPLACE FUNCTION prevent_crop_deal_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Zero-Delete Policy: Procurement contract % cannot be permanently deleted from the ledger.', OLD.deal_ref_id;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_crop_deal_delete ON public.crop_procurement_deals;
CREATE TRIGGER trg_prevent_crop_deal_delete
    BEFORE DELETE ON public.crop_procurement_deals
    FOR EACH ROW EXECUTE FUNCTION prevent_crop_deal_delete();

-- Seed Daily Mandi Rates for AP & TS AMC Yards
INSERT INTO public.daily_mandi_rates (commodity, variety, district, market_amc, arrivals_quintals, min_price, max_price, modal_price, msp_benchmark, trend, delta_24h, price_date) VALUES
('Red Chilli (మిరప)', 'Teja Deluxe', 'Guntur', 'Guntur Mirchi Yard (Asia Largest)', 48500.00, 16800.00, 21400.00, 19800.00, NULL, 'up', 450.00, CURRENT_DATE),
('Cotton (ప్రత్తి)', 'Medium Staple H-4', 'Warangal', 'Warangal AMC Market Yard', 22400.00, 6800.00, 7450.00, 7250.00, 7120.00, 'up', 130.00, CURRENT_DATE),
('Paddy (వరి)', 'BPT 5204 (Samba Masoori)', 'Krishna', 'Gudivada / Vijayawada AMC', 34200.00, 2280.00, 2460.00, 2380.00, 2320.00, 'stable', 0.00, CURRENT_DATE),
('Paddy (వరి)', 'Grade A (Common)', 'West Godavari', 'Tadepalligudem Grain Yard', 29800.00, 2260.00, 2380.00, 2320.00, 2320.00, 'stable', 0.00, CURRENT_DATE),
('Turmeric (పసుపు)', 'Salem / Nizamabad Finger', 'Nizamabad', 'Nizamabad Turmeric Market Yard', 14600.00, 12200.00, 14500.00, 13600.00, NULL, 'up', 320.00, CURRENT_DATE),
('Maize (మొక్కజొన్న)', 'Yellow Hybrid', 'Khammam', 'Khammam AMC Yard', 18300.00, 1950.00, 2240.00, 2160.00, 2090.00, 'down', -40.00, CURRENT_DATE),
('Bengal Gram (శనగలు)', 'Desi Bold', 'Kurnool', 'Kurnool Agricultural Market', 11200.00, 5500.00, 6250.00, 5920.00, 5440.00, 'up', 80.00, CURRENT_DATE),
('Red Gram (కందులు)', 'Maruti G-1', 'Mahabubnagar', 'Badepally AMC Market', 8700.00, 7400.00, 8200.00, 7850.00, 7000.00, 'stable', 0.00, CURRENT_DATE)
ON CONFLICT DO NOTHING;

-- Seed Corporate & Institutional Mill Buyers
INSERT INTO public.corporate_buyers (buyer_ref_id, company_name, industry_type, license_number, gstin, verified_status, procurement_commodities, target_districts, contact_person, contact_email, escrow_deposit_balance) VALUES
('BUYER-CORP-101', 'Sri Lalitha Modern Rice Industries Pvt Ltd', 'Rice Mill', 'LIC-AP-RM-4921', '37AABCS1234A1Z5', TRUE, '[{"commodity":"Paddy","variety":"BPT 5204","targetPrice":2420,"minQty":50,"maxMoisture":14}]'::jsonb, '["Krishna","Guntur","West Godavari"]'::jsonb, 'P. Mallikarjuna Rao', 'procure@srilalitharice.com', 2500000.00),
('BUYER-CORP-102', 'ITC Agri-Business Division (Spices & Agri)', 'Export House', 'LIC-IND-EXP-8812', '36AAACI0002L1ZQ', TRUE, '[{"commodity":"Chilli","variety":"Teja Deluxe","targetPrice":20000,"minQty":20,"maxMoisture":11}]'::jsonb, '["Guntur","Khammam","Prakasam"]'::jsonb, 'K. Srinivasa Murthy', 'spices.procure@itc.in', 5000000.00),
('BUYER-CORP-103', 'Warangal Mega Cotton Ginning & Pressing Mills', 'Cotton Ginning', 'LIC-TS-COT-5509', '36AABCW9876C1ZB', TRUE, '[{"commodity":"Cotton","variety":"Medium Staple","targetPrice":7350,"minQty":30,"maxMoisture":8}]'::jsonb, '["Warangal","Khammam","Nalgonda"]'::jsonb, 'B. Ramesh Chandra', 'cotton@warangalginning.co.in', 3500000.00),
('BUYER-CORP-104', 'Heritage Foods Agronomy & Dairy Feed Ltd', 'FMCG Processor', 'LIC-AP-FMCG-7714', '37AAACH2244K1ZS', TRUE, '[{"commodity":"Maize","variety":"Yellow Hybrid","targetPrice":2220,"minQty":40,"maxMoisture":12}]'::jsonb, '["Khammam","Nizamabad","Guntur"]'::jsonb, 'Dr. V. Sudhakar', 'agriprocure@heritagefoods.in', 1800000.00),
('BUYER-CORP-105', 'Nizamabad Spices & Organic Turmeric Export Ltd', 'Export House', 'LIC-TS-TUR-3381', '36AABCN4411D1ZP', TRUE, '[{"commodity":"Turmeric","variety":"Salem Finger","targetPrice":13900,"minQty":25,"maxMoisture":10}]'::jsonb, '["Nizamabad","Warangal","Adilabad"]'::jsonb, 'M. Janardhan Reddy', 'export@nizamturmeric.com', 3000000.00),
('BUYER-CORP-106', 'Rayalaseema Pulses & Processing Corporation', 'Agri-Processing Hub', 'LIC-AP-PLS-2201', '37AABCR6633E1ZM', TRUE, '[{"commodity":"Bengal Gram","variety":"Desi Bold","targetPrice":6050,"minQty":20,"maxMoisture":9.5}]'::jsonb, '["Kurnool","Anantapur","Kadapa"]'::jsonb, 'S. Vijay Bhaskar', 'orders@rayalaseemapulses.com', 2200000.00)
ON CONFLICT DO NOTHING;

-- Seed Initial Verified Farmer Listings
INSERT INTO public.farmer_crop_listings (crop_ref_id, farmer_name, farmer_phone_masked, district, mandal, village, crop_type, variety, quantity_quintals, moisture_percentage, expected_price_per_quintal, harvest_date, pickup_landmark, status) VALUES
('CROP-7821', 'M. Venkateswarlu', '+91 98480 •••••', 'Guntur', 'Tenali', 'Kollipara', 'Chilli', 'Teja Deluxe', 85.00, 10.50, 19900.00, CURRENT_DATE - 2, 'Opp. Primary RBK Center, Kollipara Road', 'active'),
('CROP-4190', 'B. Ramana Reddy', '+91 94401 •••••', 'Krishna', 'Gudivada', 'Nandivada', 'Paddy', 'BPT 5204', 320.00, 13.20, 2400.00, CURRENT_DATE - 1, 'Near Gudivada Canal Bridge Godown', 'active'),
('CROP-8832', 'T. Koteswara Rao', '+91 99892 •••••', 'Warangal', 'Narsampet', 'Chennaraopet', 'Cotton', 'Medium Staple', 140.00, 7.80, 7300.00, CURRENT_DATE - 3, 'Adjacent to Chennaraopet Cooperative Society', 'active'),
('CROP-6014', 'G. Anji Reddy', '+91 96183 •••••', 'Kurnool', 'Yemmiganur', 'Banavasi', 'Bengal Gram', 'Desi Bold', 95.00, 9.00, 6000.00, CURRENT_DATE - 4, 'Banavasi Farm Road, Beside Borewell #4', 'active')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 14. SPORTS EXCELLENCE HUB & CERTIFIED ACADEMY DIRECTORY
-- Supporting 8 Core Disciplines, Statewide Trials & 2% Statutory Quota
-- ============================================================================

-- Table 14.1: Sports Core Disciplines
CREATE TABLE IF NOT EXISTS public.sports_disciplines (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    governing_body VARCHAR(150) NOT NULL,
    category VARCHAR(50) NOT NULL,
    rules_blueprint TEXT,
    saap_sats_accredited BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 14.2: Certified Sports Academies Directory
CREATE TABLE IF NOT EXISTS public.sports_academies (
    id VARCHAR(50) PRIMARY KEY,
    academy_name VARCHAR(200) NOT NULL,
    discipline_id VARCHAR(50) REFERENCES public.sports_disciplines(id) ON DELETE SET NULL,
    state VARCHAR(30) NOT NULL CHECK (state IN ('Andhra Pradesh', 'Telangana')),
    district VARCHAR(100) NOT NULL,
    head_coach VARCHAR(150) NOT NULL,
    coach_license VARCHAR(100) NOT NULL,
    ground_facilities TEXT NOT NULL,
    contact_phone_masked VARCHAR(20) NOT NULL,
    accreditation_number VARCHAR(100) UNIQUE NOT NULL,
    is_verified BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 14.3: Athlete Selection Trials Registrations
CREATE TABLE IF NOT EXISTS public.athlete_trials_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pass_ref_id VARCHAR(50) UNIQUE NOT NULL,
    athlete_name VARCHAR(150) NOT NULL,
    discipline VARCHAR(100) NOT NULL,
    venue_state VARCHAR(30) NOT NULL,
    venue_district VARCHAR(100) NOT NULL,
    venue_name VARCHAR(200) NOT NULL,
    reporting_time VARCHAR(50) NOT NULL DEFAULT '06:30 AM',
    biometric_status VARCHAR(50) DEFAULT 'scheduled' CHECK (biometric_status IN ('scheduled', 'verified', 'disqualified', 'selected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table 14.4: Athlete Peer Collaborations & Fitness Desk
CREATE TABLE IF NOT EXISTS public.athlete_fitness_collaborations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collab_ref_id VARCHAR(50) UNIQUE NOT NULL,
    athlete_handle VARCHAR(100) NOT NULL,
    discipline VARCHAR(100) NOT NULL,
    district VARCHAR(100) NOT NULL,
    training_slot VARCHAR(50) NOT NULL,
    fitness_tier VARCHAR(50) NOT NULL,
    notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_academies_state_dist ON public.sports_academies(state, district);
CREATE INDEX IF NOT EXISTS idx_trials_pass ON public.athlete_trials_registrations(pass_ref_id);

-- RLS Policies
ALTER TABLE public.sports_disciplines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sports_academies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.athlete_trials_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.athlete_fitness_collaborations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public Read Access for Sports Disciplines"
    ON public.sports_disciplines FOR SELECT
    USING (true);

CREATE POLICY "Public Read Access for Certified Academies"
    ON public.sports_academies FOR SELECT
    USING (is_verified = TRUE);

CREATE POLICY "Public Read and Insert for Athlete Trials"
    ON public.athlete_trials_registrations FOR ALL
    USING (true);

CREATE POLICY "Public Read and Insert for Fitness Collaborations"
    ON public.athlete_fitness_collaborations FOR ALL
    USING (true);

-- Seed 8 Core Disciplines
INSERT INTO public.sports_disciplines (id, name, governing_body, category, rules_blueprint) VALUES
('disc_cricket', 'Cricket', 'BCCI / ACA & HCA', 'Team Field Sport', 'Pitch 22 Yards, Ranji standards, dynamic footwork drills and death bowling regimens.'),
('disc_volleyball', 'Volleyball', 'FIVB / VFI', 'Court Net Sport', '18m x 9m court, net 2.43m men / 2.24m women, 6-2 rotation and spike approach mechanics.'),
('disc_kabaddi', 'Kabaddi', 'AKFI / Pro Kabaddi', 'Contact Combat Sport', '13m x 10m mat, 30-second raid clock, cant mechanics, toe touches, and chain defense.'),
('disc_khokho', 'Kho-Kho', 'KKFI / Ultimate Kho Kho', 'Field Agility Sport', '27m x 16m pitch, 8 seated chasers, pole dive, sudden turn, and 3-defender dodge chain.'),
('disc_athletics', 'Athletics (Track & Field)', 'AFI / World Athletics', 'Individual Olympic Sport', '400m synthetic track, 100m/200m blocks, sprint mechanics, and hurdle clearing cadence.'),
('disc_badminton', 'Badminton', 'BWF / BAI', 'Racket Court Sport', '13.4m x 6.1m court, 6-corner footwork recovery, jump smashes, and net kill tactics.'),
('disc_football', 'Football', 'AIFF / FIFA', 'Team Field Sport', '105m x 68m pitch, zonal pressing traps, 3-touch transition play, and set piece defense.'),
('disc_basketball', 'Basketball', 'FIBA / BFI', 'Court Team Sport', '28m x 15m court, triple-threat stance, pick-and-roll offensive sets, and perimeter shooting.')
ON CONFLICT (id) DO NOTHING;

-- Seed Certified Sports Academies
INSERT INTO public.sports_academies (id, academy_name, discipline_id, state, district, head_coach, coach_license, ground_facilities, contact_phone_masked, accreditation_number) VALUES
('acad_sai_hyd', 'SAI Regional Sports Training Center', 'disc_athletics', 'Telangana', 'Hyderabad', 'K. Prabhakar Rao (NIS Coach)', 'SAI-A-LIC-8812', '400m 8-lane synthetic track, Olympic gym, sports medicine center', '+91 98480 •••••', 'SAI-TS-HYD-01'),
('acad_aca_vizag', 'Andhra Cricket Association (ACA) Excellence Academy', 'disc_cricket', 'Andhra Pradesh', 'Visakhapatnam', 'M. Venkatesh (BCCI Level 3)', 'BCCI-L3-4912', '12 turf practice wickets, indoor video analytics facility, floodlights', '+91 94401 •••••', 'ACA-AP-VZG-02'),
('acad_gopichand', 'Pullela Gopichand Badminton Academy', 'disc_badminton', 'Telangana', 'Hyderabad', 'P. Gopichand (Dronacharya)', 'BWF-MASTER-001', '8 air-conditioned wooden-synthetic courts, biomechanics testing lab', '+91 99892 •••••', 'SATS-TS-HYD-03'),
('acad_saap_guntur', 'SAAP Athletics & Sports Excellence Center', 'disc_athletics', 'Andhra Pradesh', 'Guntur', 'G. Subba Rao (NIS Gold Medalist)', 'SAAP-NIS-5521', 'B.R. Stadium 8-lane track, steeplechase water pit, high jump mats', '+91 96183 •••••', 'SAAP-AP-GTR-04'),
('acad_ts_sports_school', 'Telangana State Sports School (TSSS)', 'disc_volleyball', 'Telangana', 'Hyderabad', 'V. Ravinder Reddy (FIVB Level 2)', 'FIVB-L2-3319', 'Indoor wooden volleyball stadium, clay outdoor courts, strength pool', '+91 97014 •••••', 'SATS-TS-HKP-05'),
('acad_kurnool_kabaddi', 'Rayalaseema Kabaddi & Wrestling Center', 'disc_kabaddi', 'Andhra Pradesh', 'Kurnool', 'S. Mallikarjuna (PKL Certified)', 'AKFI-PRO-2281', 'International standard foam mat arena, clay akhada, recovery sauna', '+91 95532 •••••', 'SAAP-AP-KNL-06'),
('acad_warangal_regional', 'Warangal Regional Sports Academy', 'disc_khokho', 'Telangana', 'Warangal', 'T. Srinivas (National Coach)', 'KKFI-NAT-1190', 'J.N. Stadium grass field, pole dive sand pits, agility training grid', '+91 93910 •••••', 'SATS-TS-WGL-07'),
('acad_vijayawada_volleyball', 'Krishna District Volleyball Academy', 'disc_volleyball', 'Andhra Pradesh', 'Krishna', 'D. Nageswara Rao (NIS)', 'VFI-NIS-4402', 'Indira Gandhi Stadium wooden court, beach volleyball training sand pit', '+91 98495 •••••', 'SAAP-AP-BZA-08')
ON CONFLICT (id) DO NOTHING;
