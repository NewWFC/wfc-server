--
-- PostgreSQL database dump
--

-- Dumped from database version 13.14 (Debian 13.14-0+deb11u1)
-- Dumped by pg_dump version 13.14 (Debian 13.14-0+deb11u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: trusted; Type: TABLE; Schema: public; Owner: newwfc
--

CREATE TABLE public.trusted (
    id integer NOT NULL,
    profile_id bigint
);


ALTER TABLE public.trusted OWNER TO newwfc;

--
-- Name: trusted_id_seq; Type: SEQUENCE; Schema: public; Owner: newwfc
--

CREATE SEQUENCE public.trusted_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.trusted_id_seq OWNER TO newwfc;

--
-- Name: trusted_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: newwfc
--

ALTER SEQUENCE public.trusted_id_seq OWNED BY public.trusted.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: newwfc
--

CREATE TABLE public.users (
    profile_id bigint NOT NULL,
    user_id bigint NOT NULL,
    gsbrcd character varying NOT NULL,
    password character varying NOT NULL,
    ng_device_id bigint,
    email character varying NOT NULL,
    unique_nick character varying NOT NULL,
    firstname character varying,
    lastname character varying DEFAULT ''::character varying,
    mariokartwii_friend_info character varying,
    last_ip_address character varying DEFAULT ''::character varying,
    last_ingamesn character varying DEFAULT ''::character varying,
    has_ban boolean DEFAULT false,
    ban_issued timestamp without time zone,
    ban_expires timestamp without time zone,
    ban_reason character varying,
    ban_reason_hidden character varying,
    ban_moderator character varying,
    ban_tos boolean,
    open_host boolean DEFAULT false
);


ALTER TABLE public.users OWNER TO newwfc;

--
-- Name: users_profile_id_seq; Type: SEQUENCE; Schema: public; Owner: newwfc
--

CREATE SEQUENCE public.users_profile_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_profile_id_seq OWNER TO newwfc;

--
-- Name: users_profile_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: newwfc
--

ALTER SEQUENCE public.users_profile_id_seq OWNED BY public.users.profile_id;


--
-- Name: trusted id; Type: DEFAULT; Schema: public; Owner: newwfc
--

ALTER TABLE ONLY public.trusted ALTER COLUMN id SET DEFAULT nextval('public.trusted_id_seq'::regclass);


--
-- Name: users profile_id; Type: DEFAULT; Schema: public; Owner: newwfc
--

ALTER TABLE ONLY public.users ALTER COLUMN profile_id SET DEFAULT nextval('public.users_profile_id_seq'::regclass);


--
-- Name: trusted trusted_pkey; Type: CONSTRAINT; Schema: public; Owner: newwfc
--

ALTER TABLE ONLY public.trusted
    ADD CONSTRAINT trusted_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: newwfc
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (profile_id);


--
-- Name: TABLE trusted; Type: ACL; Schema: public; Owner: newwfc
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.trusted TO newwfc;


--
-- Name: SEQUENCE trusted_id_seq; Type: ACL; Schema: public; Owner: newwfc
--

GRANT ALL ON SEQUENCE public.trusted_id_seq TO newwfc;


--
-- PostgreSQL database dump complete
--

