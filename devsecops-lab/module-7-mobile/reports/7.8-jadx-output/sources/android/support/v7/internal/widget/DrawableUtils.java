package android.support.v7.internal.widget;

import android.graphics.Rect;
import android.os.Build;

/* JADX INFO: loaded from: classes.dex */
public class DrawableUtils {
    public static final Rect INSETS_NONE = new Rect();
    private static final String TAG = "DrawableUtils";
    private static Class<?> sInsetsClazz;

    static {
        if (Build.VERSION.SDK_INT >= 18) {
            try {
                sInsetsClazz = Class.forName("android.graphics.Insets");
            } catch (ClassNotFoundException e) {
            }
        }
    }

    private DrawableUtils() {
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:24:0x006a A[Catch: Exception -> 0x0071, TRY_LEAVE, TryCatch #0 {Exception -> 0x0071, blocks: (B:4:0x0005, B:6:0x001f, B:8:0x002e, B:9:0x0039, B:10:0x003c, B:11:0x003f, B:24:0x006a, B:30:0x007c, B:31:0x0083, B:32:0x008a, B:12:0x0042, B:15:0x004c, B:18:0x0056, B:21:0x0060), top: B:34:0x0005 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x007c A[Catch: Exception -> 0x0071, TRY_ENTER, TryCatch #0 {Exception -> 0x0071, blocks: (B:4:0x0005, B:6:0x001f, B:8:0x002e, B:9:0x0039, B:10:0x003c, B:11:0x003f, B:24:0x006a, B:30:0x007c, B:31:0x0083, B:32:0x008a, B:12:0x0042, B:15:0x004c, B:18:0x0056, B:21:0x0060), top: B:34:0x0005 }] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0083 A[Catch: Exception -> 0x0071, TryCatch #0 {Exception -> 0x0071, blocks: (B:4:0x0005, B:6:0x001f, B:8:0x002e, B:9:0x0039, B:10:0x003c, B:11:0x003f, B:24:0x006a, B:30:0x007c, B:31:0x0083, B:32:0x008a, B:12:0x0042, B:15:0x004c, B:18:0x0056, B:21:0x0060), top: B:34:0x0005 }] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008a A[Catch: Exception -> 0x0071, TRY_LEAVE, TryCatch #0 {Exception -> 0x0071, blocks: (B:4:0x0005, B:6:0x001f, B:8:0x002e, B:9:0x0039, B:10:0x003c, B:11:0x003f, B:24:0x006a, B:30:0x007c, B:31:0x0083, B:32:0x008a, B:12:0x0042, B:15:0x004c, B:18:0x0056, B:21:0x0060), top: B:34:0x0005 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x003f A[SYNTHETIC] */
    /*  JADX ERROR: UnsupportedOperationException in pass: RegionMakerVisitor
        java.lang.UnsupportedOperationException
        	at java.base/java.util.Collections$UnmodifiableCollection.add(Collections.java:1093)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker$1.leaveRegion(SwitchRegionMaker.java:390)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:70)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverse(DepthRegionTraversal.java:23)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker.insertBreaksForCase(SwitchRegionMaker.java:370)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker.insertBreaks(SwitchRegionMaker.java:85)
        	at jadx.core.dex.visitors.regions.PostProcessRegions.leaveRegion(PostProcessRegions.java:33)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:70)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at java.base/java.util.Collections$UnmodifiableCollection.forEach(Collections.java:1118)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at java.base/java.util.Collections$UnmodifiableCollection.forEach(Collections.java:1118)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.lambda$traverseInternal$0(DepthRegionTraversal.java:68)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1604)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseInternal(DepthRegionTraversal.java:68)
        	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverse(DepthRegionTraversal.java:19)
        	at jadx.core.dex.visitors.regions.PostProcessRegions.process(PostProcessRegions.java:23)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:31)
        */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Rect getOpticalBounds(android.graphics.drawable.Drawable r12) {
        /*
            r9 = 0
            java.lang.Class<?> r8 = android.support.v7.internal.widget.DrawableUtils.sInsetsClazz
            if (r8 == 0) goto L79
            android.graphics.drawable.Drawable r12 = android.support.v4.graphics.drawable.DrawableCompat.unwrap(r12)     // Catch: java.lang.Exception -> L71
            java.lang.Class r8 = r12.getClass()     // Catch: java.lang.Exception -> L71
            java.lang.String r10 = "getOpticalInsets"
            r11 = 0
            java.lang.Class[] r11 = new java.lang.Class[r11]     // Catch: java.lang.Exception -> L71
            java.lang.reflect.Method r3 = r8.getMethod(r10, r11)     // Catch: java.lang.Exception -> L71
            r8 = 0
            java.lang.Object[] r8 = new java.lang.Object[r8]     // Catch: java.lang.Exception -> L71
            java.lang.Object r5 = r3.invoke(r12, r8)     // Catch: java.lang.Exception -> L71
            if (r5 == 0) goto L79
            android.graphics.Rect r7 = new android.graphics.Rect     // Catch: java.lang.Exception -> L71
            r7.<init>()     // Catch: java.lang.Exception -> L71
            java.lang.Class<?> r8 = android.support.v7.internal.widget.DrawableUtils.sInsetsClazz     // Catch: java.lang.Exception -> L71
            java.lang.reflect.Field[] r0 = r8.getFields()     // Catch: java.lang.Exception -> L71
            int r6 = r0.length     // Catch: java.lang.Exception -> L71
            r4 = 0
        L2c:
            if (r4 >= r6) goto L7b
            r2 = r0[r4]     // Catch: java.lang.Exception -> L71
            java.lang.String r10 = r2.getName()     // Catch: java.lang.Exception -> L71
            r8 = -1
            int r11 = r10.hashCode()     // Catch: java.lang.Exception -> L71
            switch(r11) {
                case -1383228885: goto L60;
                case 115029: goto L4c;
                case 3317767: goto L42;
                case 108511772: goto L56;
                default: goto L3c;
            }     // Catch: java.lang.Exception -> L71
        L3c:
            switch(r8) {
                case 0: goto L6a;
                case 1: goto L7c;
                case 2: goto L83;
                case 3: goto L8a;
                default: goto L3f;
            }     // Catch: java.lang.Exception -> L71
        L3f:
            int r4 = r4 + 1
            goto L2c
        L42:
            java.lang.String r11 = "left"
            boolean r10 = r10.equals(r11)     // Catch: java.lang.Exception -> L71
            if (r10 == 0) goto L3c
            r8 = r9
            goto L3c
        L4c:
            java.lang.String r11 = "top"
            boolean r10 = r10.equals(r11)     // Catch: java.lang.Exception -> L71
            if (r10 == 0) goto L3c
            r8 = 1
            goto L3c
        L56:
            java.lang.String r11 = "right"
            boolean r10 = r10.equals(r11)     // Catch: java.lang.Exception -> L71
            if (r10 == 0) goto L3c
            r8 = 2
            goto L3c
        L60:
            java.lang.String r11 = "bottom"
            boolean r10 = r10.equals(r11)     // Catch: java.lang.Exception -> L71
            if (r10 == 0) goto L3c
            r8 = 3
            goto L3c
        L6a:
            int r8 = r2.getInt(r5)     // Catch: java.lang.Exception -> L71
            r7.left = r8     // Catch: java.lang.Exception -> L71
            goto L3f
        L71:
            r1 = move-exception
            java.lang.String r8 = "DrawableUtils"
            java.lang.String r9 = "Couldn't obtain the optical insets. Ignoring."
            android.util.Log.e(r8, r9)
        L79:
            android.graphics.Rect r7 = android.support.v7.internal.widget.DrawableUtils.INSETS_NONE
        L7b:
            return r7
        L7c:
            int r8 = r2.getInt(r5)     // Catch: java.lang.Exception -> L71
            r7.top = r8     // Catch: java.lang.Exception -> L71
            goto L3f
        L83:
            int r8 = r2.getInt(r5)     // Catch: java.lang.Exception -> L71
            r7.right = r8     // Catch: java.lang.Exception -> L71
            goto L3f
        L8a:
            int r8 = r2.getInt(r5)     // Catch: java.lang.Exception -> L71
            r7.bottom = r8     // Catch: java.lang.Exception -> L71
            goto L3f
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v7.internal.widget.DrawableUtils.getOpticalBounds(android.graphics.drawable.Drawable):android.graphics.Rect");
    }
}
