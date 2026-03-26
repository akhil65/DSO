package android.support.design.widget;

/* JADX INFO: loaded from: classes.dex */
class MathUtils {
    MathUtils() {
    }

    static int constrain(int amount, int low, int high) {
        return amount < low ? low : amount > high ? high : amount;
    }

    static float constrain(float amount, float low, float high) {
        return amount < low ? low : amount > high ? high : amount;
    }
}
