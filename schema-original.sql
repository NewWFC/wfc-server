--
-- PostgreSQL database dump
--

-- Dumped from database version 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.9 (Homebrew)

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
-- Name: users; Type: TABLE; Schema: public; Owner: wiilink
--

CREATE TABLE IF NOT EXISTS public.users (
    profile_id bigint NOT NULL,
    user_id bigint NOT NULL,
    gsbrcd character varying NOT NULL,
    password character varying NOT NULL,
    ng_device_id bigint,
    email character varying NOT NULL,
    unique_nick character varying NOT NULL,
    firstname character varying,
    lastname character varying DEFAULT ''::character varying,
    mariokartwii_friend_info character varying
);


ALTER TABLE ONLY public.users
    ADD IF NOT EXISTS last_ip_address character varying DEFAULT ''::character varying,
    ADD IF NOT EXISTS last_ingamesn character varying DEFAULT ''::character varying,
    ADD IF NOT EXISTS has_ban boolean DEFAULT false,
    ADD IF NOT EXISTS ban_issued timestamp without time zone,
    ADD IF NOT EXISTS ban_expires timestamp without time zone,
    ADD IF NOT EXISTS ban_reason character varying,
    ADD IF NOT EXISTS ban_reason_hidden character varying,
    ADD IF NOT EXISTS ban_moderator character varying,
    ADD IF NOT EXISTS ban_tos boolean


ALTER TABLE public.users OWNER TO wiilink;

--
-- Name: users_profile_id_seq; Type: SEQUENCE; Schema: public; Owner: wiilink
--

CREATE SEQUENCE IF NOT EXISTS public.users_profile_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_profile_id_seq OWNER TO wiilink;

--
-- Name: users_profile_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wiilink
--

ALTER SEQUENCE public.users_profile_id_seq OWNED BY public.users.profile_id;

--
-- Name: users profile_id; Type: DEFAULT; Schema: public; Owner: wiilink
--

ALTER TABLE ONLY public.users ALTER COLUMN profile_id SET DEFAULT nextval('public.users_profile_id_seq'::regclass);

--
-- Set the profile_id start point to 1'000'000'000
--

ALTER SEQUENCE users_profile_id_seq RESTART WITH 1000000000;

--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: wiilink
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (profile_id);


--
-- PostgreSQL database dump complete
--

