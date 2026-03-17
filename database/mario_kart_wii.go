package database

import (
	"context"
	"time"
	"wwfc/common"

	"github.com/jackc/pgx/v4/pgxpool"
)

type MarioKartWiiTopTenRanking struct {
	Score      int
	PID        int
	PlayerInfo string
}

type MarioKartWiiTopTenRankingBAN struct {
	Score      int
	PID        int
	PlayerInfo string
	STime      time.Time
	Hidden     bool
}

const (
	getTopTenRankingsQuery = "" +
		"SELECT score, pid, playerinfo " +
		"FROM mario_kart_wii_sake " +
		"WHERE ($1 = 0 OR regionid = $1) " +
		"AND courseid = $2 " +
		"ORDER BY score ASC " +
		"LIMIT 10"
	getTop50RankingsQueryttbanned = "" +
		"SELECT m.score, m.pid, m.playerinfo, m.upload_time, " +
		"CASE WHEN t.pid IS NOT NULL THEN TRUE ELSE FALSE END AS banned " +
		"FROM mario_kart_wii_sake m " +
		"LEFT JOIN ttsban t ON m.pid = t.pid " +
		"WHERE ($1 = 0 OR m.regionid = $1) " +
		"AND m.courseid = $2 " +
		"ORDER BY m.score ASC " +
		"LIMIT 50"
	getGhostDataQuery = "" +
		"SELECT id " +
		"FROM mario_kart_wii_sake " +
		"WHERE courseid = $1 " +
		"AND score < $2 " +
		"ORDER BY score DESC " +
		"LIMIT 1"
	getStoredGhostDataQuery = "" +
		"SELECT pid, id " +
		"FROM mario_kart_wii_sake " +
		"WHERE ($1 = 0 OR regionid = $1) " +
		"AND courseid = $2 " +
		"ORDER BY score ASC " +
		"LIMIT 1"
	getFileQuery = "" +
		"SELECT ghost " +
		"FROM mario_kart_wii_sake " +
		"WHERE id = $1 " +
		"LIMIT 1"
	getGhostFileQuery = "" +
		"SELECT ghost " +
		"FROM mario_kart_wii_sake " +
		"WHERE courseid = $1 " +
		"AND score < $2 " +
		"AND pid <> $3 " +
		"ORDER BY score DESC " +
		"LIMIT 1"
	insertGhostFileStatement = "" +
		"INSERT INTO mario_kart_wii_sake (regionid, courseid, score, pid, playerinfo, ghost, upload_time) " +
		"VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) " +
		"ON CONFLICT (courseid, pid) DO UPDATE " +
		"SET regionid = EXCLUDED.regionid, score = EXCLUDED.score, playerinfo = EXCLUDED.playerinfo, ghost = EXCLUDED.ghost, upload_time = CURRENT_TIMESTAMP"
)

func GetMarioKartWiiTopTenRankings(pool *pgxpool.Pool, ctx context.Context, regionId common.MarioKartWiiLeaderboardRegionId,
	courseId common.MarioKartWiiCourseId) ([]MarioKartWiiTopTenRanking, error) {
	rows, err := pool.Query(ctx, getTopTenRankingsQuery, regionId, courseId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	topTenRankings := make([]MarioKartWiiTopTenRanking, 0, 10)
	for rows.Next() {
		var topTenRanking MarioKartWiiTopTenRanking
		err = rows.Scan(&topTenRanking.Score, &topTenRanking.PID, &topTenRanking.PlayerInfo)
		if err != nil {
			return nil, err
		}

		topTenRankings = append(topTenRankings, topTenRanking)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return topTenRankings, nil
}

func GetMarioKartWiiGhostData(pool *pgxpool.Pool, ctx context.Context, courseId common.MarioKartWiiCourseId, time int) (int, error) {
	row := pool.QueryRow(ctx, getGhostDataQuery, courseId, time)

	var fileId int
	if err := row.Scan(&fileId); err != nil {
		return 0, err
	}

	return fileId, nil
}

func GetMarioKartWiiStoredGhostData(pool *pgxpool.Pool, ctx context.Context, regionId common.MarioKartWiiLeaderboardRegionId,
	courseId common.MarioKartWiiCourseId) (int, int, error) {
	row := pool.QueryRow(ctx, getStoredGhostDataQuery, regionId, courseId)

	var pid int
	var fileId int
	if err := row.Scan(&pid, &fileId); err != nil {
		return 0, 0, err
	}

	return pid, fileId, nil
}

func GetMarioKartWiiFile(pool *pgxpool.Pool, ctx context.Context, fileId int) ([]byte, error) {
	row := pool.QueryRow(ctx, getFileQuery, fileId)

	var file []byte
	if err := row.Scan(&file); err != nil {
		return nil, err
	}

	return file, nil
}

func GetMarioKartWiiGhostFile(pool *pgxpool.Pool, ctx context.Context, courseId common.MarioKartWiiCourseId,
	time int, pid int) ([]byte, error) {
	row := pool.QueryRow(ctx, getGhostFileQuery, courseId, time, pid)

	var ghost []byte
	if err := row.Scan(&ghost); err != nil {
		return nil, err
	}

	return ghost, nil
}

func InsertMarioKartWiiGhostFile(pool *pgxpool.Pool, ctx context.Context, regionId common.MarioKartWiiLeaderboardRegionId,
	courseId common.MarioKartWiiCourseId, score int, pid int, playerInfo string, ghost []byte) error {
	_, err := pool.Exec(ctx, insertGhostFileStatement, regionId, courseId, score, pid, playerInfo, ghost)

	return err
}

// func TimeTrials(pool *pgxpool.Pool, ctx context.Context, regionId common.MarioKartWiiLeaderboardRegionId,
//
//	courseId common.MarioKartWiiCourseId, hidden bool) ([]MarioKartWiiTopTenRanking, error) {
//	rows, err := pool.Query(ctx, getTopTenRankingsQuery, regionId, courseId)
func TimeTrials(pool *pgxpool.Pool, ctx context.Context, regionId uint8,
	courseId uint8, hidden bool) ([]MarioKartWiiTopTenRankingBAN, error) {
	rows, err := pool.Query(ctx, getTop50RankingsQueryttbanned, regionId, courseId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	topTenRankings := make([]MarioKartWiiTopTenRankingBAN, 0, 50)
	for rows.Next() {
		var topTenRanking MarioKartWiiTopTenRankingBAN
		err = rows.Scan(&topTenRanking.Score, &topTenRanking.PID, &topTenRanking.PlayerInfo, &topTenRanking.STime, &topTenRanking.Hidden)
		if err != nil {
			return nil, err
		}

		topTenRankings = append(topTenRankings, topTenRanking)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return topTenRankings, nil
}
