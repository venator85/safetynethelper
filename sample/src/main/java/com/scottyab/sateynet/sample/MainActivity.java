package com.scottyab.sateynet.sample;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.annotation.TargetApi;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import com.scottyab.safetynet.AttestationStatement;
import com.scottyab.safetynet.SafetyNetHelper;
import com.scottyab.safetynet.SafetyNetVerificationException;
import com.scottyab.safetynet.Utils;
import com.scottyab.safetynet.sample.BuildConfig;
import com.scottyab.safetynet.sample.R;

import java.util.Arrays;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SafetyNetHelperSAMPLE";

	private View loading;

    private SafetyNetHelper safetyNetHelper;
    private AttestationStatement lastAttestationStatement;

    private TextView resultsTV;
    private View resultsContainer;
    private ImageView resultsIcon;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        safetyNetHelper = new SafetyNetHelper(BuildConfig.GOOGLE_VERIFICATION_API_KEY);

        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());

        initViews();
    }

    private void initViews() {
        resultsTV = (TextView) findViewById(R.id.results);
        resultsContainer = findViewById(R.id.resultsContainer);
        loading = findViewById(R.id.loading);
        resultsIcon = (ImageView) findViewById(R.id.resultIcon);

        findViewById(R.id.runTestButton).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runTest();
            }
        });
    }

    private void runTest() {
        showLoading(true);

        Log.d(TAG, "SafetyNet start request");
        safetyNetHelper.requestTest(this, new SafetyNetHelper.SafetyNetWrapperCallback() {
	        @Override
	        public void error(Exception e) {
		        showLoading(false);
		        handleError(false, e);
	        }

            @Override
            public void success(AttestationStatement response) {
                Log.d(TAG, "SafetyNet req success: " + response);
	            lastAttestationStatement = response;
                showLoading(false);
                updateUIWithSuccessfulResult(response);
            }

	        @Override
	        public void failure(SafetyNetVerificationException e) {
		        showLoading(false);
		        handleError(true, e);
	        }
        });
    }

	private void handleError(boolean failure, Exception e) {
		resultsTV.setText(failure ? "Failure" : "Error");
		String msg;
		if (e instanceof SafetyNetVerificationException) {
			SafetyNetVerificationException sfe = (SafetyNetVerificationException) e;
			msg = sfe.getErrorCode() + " - " + e.toString();
			if (sfe.getResponse() != null) {
				msg += "\nresponse: " + attestationStmtToString(sfe.getResponse());
			}
		} else {
			msg = e.toString();
		}
		resultsTV.setText(msg);

		if (failure) {
			resultsIcon.setImageResource(R.drawable.fail);
		} else {
			resultsIcon.setImageResource(R.drawable.problem);
		}
		revealResults(ContextCompat.getColor(this, R.color.problem));
	}

    private void showLoading(boolean show) {
        loading.setVisibility(show ? View.VISIBLE : View.GONE);
        if (show) {
            resultsContainer.setBackgroundColor(Color.TRANSPARENT);
            resultsContainer.setVisibility(View.GONE);
        }
    }

    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    private void revealResults(Integer colorTo) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
            doPropertyAnimatorReveal(colorTo);
            resultsContainer.setVisibility(View.VISIBLE);
        } else {
            resultsContainer.setVisibility(View.VISIBLE);
        }
    }

    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    private void doPropertyAnimatorReveal(Integer colorTo) {
        Integer colorFrom = Color.TRANSPARENT;
        Drawable background = resultsContainer.getBackground();
        if (background instanceof ColorDrawable) {
            colorFrom = ((ColorDrawable) background).getColor();
        }

        ValueAnimator colorAnimation = ValueAnimator.ofObject(new ArgbEvaluator(), colorFrom, colorTo);
        colorAnimation.setDuration(500);
        colorAnimation.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animator) {
                resultsContainer.setBackgroundColor((Integer) animator.getAnimatedValue());
            }

        });
        colorAnimation.start();
    }

    private void updateUIWithSuccessfulResult(AttestationStatement safetyNetResponse) {
	    resultsTV.setText(attestationStmtToString(safetyNetResponse));

        resultsIcon.setImageResource(safetyNetResponse.isCtsProfileMatch() ? R.drawable.pass : R.drawable.fail);

        revealResults(ContextCompat.getColor(this, safetyNetResponse.isCtsProfileMatch() ? R.color.pass : R.color.fail));
    }

	@NonNull
	private String attestationStmtToString(AttestationStatement safetyNetResponse) {
		return "AttestationStatement{\n" +
				    "  nonce='" + android.util.Base64.encodeToString(safetyNetResponse.getNonce(), android.util.Base64.NO_WRAP) + '\'' +
				    ",\n  timestampMs=" + safetyNetResponse.getTimestampMs() +
				    ",\n  apkPackageName='" + safetyNetResponse.getApkPackageName() + '\'' +
				    ",\n  apkCertificateDigestSha256=" + Arrays.toString(safetyNetResponse.getApkCertificateDigestSha256()) +
				    ",\n  apkDigestSha256='" + safetyNetResponse.getApkDigestSha256() + '\'' +
				    ",\n  ctsProfileMatch=" + safetyNetResponse.isCtsProfileMatch() +
				    ",\n  basicIntegrity=" + safetyNetResponse.isBasicIntegrity() +
				    ",\n  advice='" + safetyNetResponse.getAdvice() + '\'' +
				    "\n}";
	}

	@Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_info) {
            SampleAppUtils.showInfoDialog(this);
            return true;
        } else if (id == R.id.action_sharee) {
            SampleAppUtils.shareTestResults(this, lastAttestationStatement);
            return true;
        } else if (id == R.id.action_github) {
            SampleAppUtils.openGitHubProjectPage(this);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }


}
