package android.support.v7.widget;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.support.v7.internal.widget.TintInfo;
import android.support.v7.internal.widget.TintManager;
import android.util.AttributeSet;
import android.widget.TextView;

/* JADX INFO: loaded from: classes.dex */
class AppCompatTextHelperV17 extends AppCompatTextHelper {
    private static final int[] VIEW_ATTRS_v17 = {R.attr.drawableStart, R.attr.drawableEnd};
    private TintInfo mDrawableEndTint;
    private TintInfo mDrawableStartTint;

    AppCompatTextHelperV17(TextView view) {
        super(view);
    }

    @Override // android.support.v7.widget.AppCompatTextHelper
    void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        super.loadFromAttributes(attrs, defStyleAttr);
        Context context = this.mView.getContext();
        TintManager tintManager = TintManager.get(context);
        TypedArray a = context.obtainStyledAttributes(attrs, VIEW_ATTRS_v17, defStyleAttr, 0);
        if (a.hasValue(0)) {
            this.mDrawableStartTint = new TintInfo();
            this.mDrawableStartTint.mHasTintList = true;
            this.mDrawableStartTint.mTintList = tintManager.getTintList(a.getResourceId(0, 0));
        }
        if (a.hasValue(1)) {
            this.mDrawableEndTint = new TintInfo();
            this.mDrawableEndTint.mHasTintList = true;
            this.mDrawableEndTint.mTintList = tintManager.getTintList(a.getResourceId(1, 0));
        }
        a.recycle();
    }

    @Override // android.support.v7.widget.AppCompatTextHelper
    void applyCompoundDrawablesTints() {
        super.applyCompoundDrawablesTints();
        if (this.mDrawableStartTint != null || this.mDrawableEndTint != null) {
            Drawable[] compoundDrawables = this.mView.getCompoundDrawablesRelative();
            applyCompoundDrawableTint(compoundDrawables[0], this.mDrawableStartTint);
            applyCompoundDrawableTint(compoundDrawables[2], this.mDrawableEndTint);
        }
    }
}
