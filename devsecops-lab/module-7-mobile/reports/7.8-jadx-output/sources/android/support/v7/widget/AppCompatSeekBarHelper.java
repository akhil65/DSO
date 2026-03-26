package android.support.v7.widget;

import android.R;
import android.graphics.drawable.Drawable;
import android.support.v7.internal.widget.TintManager;
import android.support.v7.internal.widget.TintTypedArray;
import android.util.AttributeSet;
import android.widget.SeekBar;

/* JADX INFO: loaded from: classes.dex */
class AppCompatSeekBarHelper extends AppCompatProgressBarHelper {
    private static final int[] TINT_ATTRS = {R.attr.thumb};
    private final SeekBar mView;

    AppCompatSeekBarHelper(SeekBar view, TintManager tintManager) {
        super(view, tintManager);
        this.mView = view;
    }

    @Override // android.support.v7.widget.AppCompatProgressBarHelper
    void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        super.loadFromAttributes(attrs, defStyleAttr);
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(this.mView.getContext(), attrs, TINT_ATTRS, defStyleAttr, 0);
        Drawable drawable = a.getDrawableIfKnown(0);
        if (drawable != null) {
            this.mView.setThumb(drawable);
        }
        a.recycle();
    }
}
