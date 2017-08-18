package com.scottyab.sateynet.sample;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.annotation.TargetApi;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Base64;
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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SafetyNetHelperSAMPLE";

    //*** REPLACE with your own!! ***
    private static final String API_KEY = BuildConfig.GOOGLE_VERIFICATION_API_KEY;
    private View loading;

    private SafetyNetHelper safetyNetHelper;
    private AttestationStatement lastAttestationStatement;

    private TextView resultsTV;
    private TextView nonceTV;
    private TextView timestampTV;
    private View resultsContainer;
    private ImageView resultsIcon;
    private View successResultsContainer;
    private TextView packageNameTV;
    private TextView resultNoteTV;
    private TextView welcomeTV;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        safetyNetHelper = new SafetyNetHelper(API_KEY);

        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());

        initViews();
    }

    private void initViews() {
        welcomeTV = (TextView) findViewById(R.id.welcomeTV);
        resultsTV = (TextView) findViewById(R.id.results);
        resultNoteTV = (TextView) findViewById(R.id.resultsNote);
        nonceTV = (TextView) findViewById(R.id.nonce);
        timestampTV = (TextView) findViewById(R.id.timestamp);
        packageNameTV = (TextView) findViewById(R.id.packagename);
        resultsContainer = findViewById(R.id.resultsContainer);
        successResultsContainer = findViewById(R.id.sucessResultsContainer);
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
			msg = ((SafetyNetVerificationException) e).getErrorCode() + "\n" + e.toString();
		} else {
			msg = e.toString();
		}
		resultNoteTV.setText(msg);

		resultsIcon.setImageResource(R.drawable.problem);
		successResultsContainer.setVisibility(View.GONE);
		welcomeTV.setVisibility(View.GONE);
		revealResults(ContextCompat.getColor(this, R.color.problem));
	}

    private void showLoading(boolean show) {
        loading.setVisibility(show ? View.VISIBLE : View.GONE);
        if (show) {
            resultsContainer.setBackgroundColor(Color.TRANSPARENT);
            resultsContainer.setVisibility(View.GONE);
            welcomeTV.setVisibility(View.GONE);
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
        resultsTV.setText(getString(R.string.safety_results, safetyNetResponse.isCtsProfileMatch(), safetyNetResponse.isBasicIntegrity()));
        if (!TextUtils.isEmpty(safetyNetResponse.getAdvice())) {
	        resultsTV.append("\nAdvice: ");
	        resultsTV.append(safetyNetResponse.getAdvice());
        }
        resultNoteTV.setText(R.string.safety_results_note);

        successResultsContainer.setVisibility(View.VISIBLE);

        nonceTV.setText(Base64.encodeToString(safetyNetResponse.getNonce(), Base64.NO_WRAP));

        SimpleDateFormat sim = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault());
        Date timeOfResponse = new Date(safetyNetResponse.getTimestampMs());
        timestampTV.setText(sim.format(timeOfResponse));
        packageNameTV.setText(safetyNetResponse.getApkPackageName());

        resultsIcon.setImageResource(safetyNetResponse.isCtsProfileMatch() ? R.drawable.pass : R.drawable.fail);

        revealResults(ContextCompat.getColor(this, safetyNetResponse.isCtsProfileMatch() ? R.color.pass : R.color.fail));
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
