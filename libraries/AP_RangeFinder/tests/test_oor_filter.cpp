#include <AP_gtest.h>
#include <AP_RangeFinder/AP_RangeFinder_PulsedLightLRF.h>

// Aliases for readability
using R  = AP_RangeFinder_PulsedLightLRF;
using St = RangeFinder::Status;

static constexpr uint16_t MAX_CM = 4000;
static constexpr uint16_t MIN_CM = 5;
static constexpr uint16_t OOR_THRESHOLD = MAX_CM - MAX_CM / 5;  // 3200

// Helper: single call
static R::CollectResult p(uint16_t reading, uint16_t last, uint32_t last_ms, uint32_t now)
{
    return R::process_distance_reading(reading, last, last_ms, MAX_CM, MIN_CM, now);
}

// -----------------------------------------------------------------------
// Happy paths
// -----------------------------------------------------------------------

TEST(OORFilter, HighAltitudeStableReadings)
{
    // Smooth readings near max range → all Good, baseline tracks
    uint16_t last = 3500; uint32_t last_ms = 0;
    for (uint16_t r : {3510, 3500, 3520, 3495, 3505}) {
        auto res = p(r, last, last_ms, last_ms + 20);
        EXPECT_EQ(res.status, St::Good);
        EXPECT_GT(res.distance_m, 30.0f);
        last = res.last_distance_cm; last_ms = res.last_reading_ms;
    }
}

TEST(OORFilter, LowAltitudeStableReadings)
{
    // Close to ground → Good, distance below deploy threshold
    uint16_t last = 50; uint32_t last_ms = 0;
    for (uint16_t r : {48, 45, 42, 38, 35}) {
        auto res = p(r, last, last_ms, last_ms + 20);
        EXPECT_EQ(res.status, St::Good);
        EXPECT_LT(res.distance_m, 1.0f);
        last = res.last_distance_cm; last_ms = res.last_reading_ms;
    }
}

TEST(OORFilter, SmoothDescentDeploys)
{
    // 50cm steps: delta always < 100 → all Good
    uint16_t last = 650; uint32_t last_ms = 0;
    for (int r = 600; r >= 50; r -= 50) {
        auto res = p(uint16_t(r), last, last_ms, last_ms + 40);
        EXPECT_EQ(res.status, St::Good) << "reading=" << r;
        last = res.last_distance_cm; last_ms = res.last_reading_ms;
    }
    EXPECT_LT(last, 300);
}

// -----------------------------------------------------------------------
// OOR artifact suppression
// -----------------------------------------------------------------------

TEST(OORFilter, OORartifactSuppressed)
{
    // last=3900 (>3200), reading=1 (<5) → OutOfRangeHigh, baseline preserved
    for (int i = 0; i < 6; i++) {
        auto res = p(1, 3900, uint32_t(i * 20), uint32_t((i + 1) * 20));
        EXPECT_EQ(res.status, St::OutOfRangeHigh) << "cycle " << i;
        EXPECT_EQ(res.last_distance_cm, 3900) << "baseline must be preserved cycle " << i;
    }
}

TEST(OORFilter, OORrecoveryToHighAltitude)
{
    // 3 OOR artifacts, then valid high reading → recovers
    uint16_t last = 3900; uint32_t last_ms = 1000;
    for (int i = 0; i < 3; i++) {
        auto res = p(1, last, last_ms, last_ms + 20);
        EXPECT_EQ(res.status, St::OutOfRangeHigh);
        last = res.last_distance_cm; last_ms = res.last_reading_ms;
    }
    auto res = p(3850, last, last_ms, last_ms + 20);
    EXPECT_EQ(res.status, St::Good);
    EXPECT_EQ(res.last_distance_cm, 3850);
}

// -----------------------------------------------------------------------
// Boundary conditions (expected to expose weaknesses)
// -----------------------------------------------------------------------

TEST(OORFilter, ReadingAtMinDist_IsOOR_WithHighBaseline)
{
    // reading = MIN_CM (5) with high baseline: now correctly caught as OOR artifact (<=).
    // A genuine 5cm landing never reaches this state — the baseline would already be
    // near 5cm after smooth descent. 5cm + baseline 3900cm = artifact, not landing.
    auto res = p(MIN_CM, 3900, 1000, 1020);
    EXPECT_EQ(res.status, St::OutOfRangeHigh);
    EXPECT_EQ(res.last_distance_cm, 3900);   // baseline preserved
}

TEST(OORFilter, LastAtExactOORThreshold_NotProtected)
{
    // last = 3200 (exactly 80% of max). OOR condition: 3200 > 3200 → FALSE.
    // 1cm reading is NOT caught as OOR artifact. Filter is unprotected at boundary.
    // WEAKNESS: use >= instead of > to fix.
    auto res = p(1, OOR_THRESHOLD, 1000, 1020);
    EXPECT_EQ(res.status, St::OutOfRangeHigh)
        << "WEAKNESS: OOR filter not triggered at exact 80% threshold (3200 > 3200 is false)";
}

TEST(OORFilter, DeltaExactly100_NotAccepted)
{
    // delta = |300-200| = 100, NOT < 100 → NoData/Ignored. 99 would be Good.
    // WEAKNESS: use <= instead of < to fix.
    auto blocked = p(300, 200, 1000, 1020);
    auto fine    = p(299, 200, 1000, 1020);
    EXPECT_EQ(fine.status, St::Good);
    EXPECT_EQ(blocked.status, St::Good)
        << "WEAKNESS: delta=100cm exactly is blocked (< 100 is exclusive)";
}

TEST(OORFilter, BaselineResetAtExactly100ms)
{
    // now - last_ms >= 100 triggers baseline reset (fixed: was > 100).
    // Status is NoData (reading not reported), but baseline moves to new value.
    auto at100  = p(700, 200, 1000, 1100);  // exactly 100ms
    auto at101  = p(700, 200, 1000, 1101);  // 101ms

    EXPECT_EQ(at100.status, St::NoData);
    EXPECT_EQ(at100.last_distance_cm, 700);  // baseline reset

    EXPECT_EQ(at101.status, St::NoData);
    EXPECT_EQ(at101.last_distance_cm, 700);  // baseline reset
}

TEST(OORFilter, OORartifactsThenStableRecovery)
{
    // OOR artifacts do NOT update last_reading_ms (fixed).
    // After 100ms of OOR silence, the first stable low reading triggers BaselineReset,
    // and subsequent stable readings are accepted as Good.
    uint16_t last = 3900; uint32_t last_ms = 1000;
    uint32_t now = 1000;

    // 6 OOR artifacts at 20ms each = 120ms of OOR
    for (int i = 0; i < 6; i++) {
        now += 20;
        auto res = p(1, last, last_ms, now);
        EXPECT_EQ(res.status, St::OutOfRangeHigh);
        last = res.last_distance_cm;
        last_ms = res.last_reading_ms;  // should not change
    }
    EXPECT_EQ(last_ms, 1000);  // last_reading_ms untouched during OOR

    // First stable low reading after 120ms → BaselineReset
    now += 20;
    auto reset = p(200, last, last_ms, now);
    EXPECT_EQ(reset.status, St::NoData);           // BaselineReset, not reported yet
    EXPECT_EQ(reset.last_distance_cm, 200);         // baseline moved to 200
    last = reset.last_distance_cm; last_ms = reset.last_reading_ms;

    // Subsequent stable readings near 200cm → Good
    for (uint16_t r : {205, 195, 200, 198}) {
        now += 20;
        auto res = p(r, last, last_ms, now);
        EXPECT_EQ(res.status, St::Good) << "reading=" << r;
        last = res.last_distance_cm; last_ms = res.last_reading_ms;
    }
}

TEST(OORFilter, GenuineObstacleSuppressedAsOOR)
{
    // Aircraft at 3500cm. Bird at 2cm from sensor.
    // OOR filter fires → obstacle silently discarded.
    // WEAKNESS: filter cannot distinguish OOR artifact from real close obstacle.
    auto res = p(2, 3500, 1000, 1020);
    EXPECT_NE(res.status, St::OutOfRangeHigh)
        << "WEAKNESS: genuine 2cm obstacle at high altitude suppressed as OOR artifact";
}

AP_GTEST_MAIN()
