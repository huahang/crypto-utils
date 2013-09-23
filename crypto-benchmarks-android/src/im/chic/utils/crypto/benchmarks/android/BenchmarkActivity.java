package im.chic.utils.crypto.benchmarks.android;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.TextView;
import im.chic.utils.crypto.benchmarks.AesBenchmark;
import im.chic.utils.crypto.benchmarks.DigestBenchmark;
import im.chic.utils.crypto.benchmarks.Rc4Benchmark;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class BenchmarkActivity extends Activity {

    private TextView debug = null;

    @Override
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.main);
        debug = (TextView) findViewById(R.id.debug);
        refresh();
    }

    private void refresh() {
        AsyncTask<Void, String, String> refreshTask = new AsyncTask<Void, String, String>() {
            @Override
            protected void onPreExecute() {
                debug.setText("Running...");
            }

            @Override
            protected String doInBackground(Void... params) {
                String result = "";
                try {
                    result += Rc4Benchmark.runRc4_JCE();
                    publishProgress(result);
                    result += Rc4Benchmark.runRc4();
                    publishProgress(result);
                    result += DigestBenchmark.runSha1_JCE();
                    publishProgress(result);
                    result += DigestBenchmark.runSha1();
                    publishProgress(result);
                    result += AesBenchmark.runAesEcbPkcs5_JCE();
                    publishProgress(result);
                    result += AesBenchmark.runAesEcbPkcs5();
                    publishProgress(result);
                    result += AesBenchmark.runAesCbcPkcs5_JCE();
                    publishProgress(result);
                    result += AesBenchmark.runAesCbcPkcs5();
                    publishProgress(result);
                } catch (IOException e) {
                    result = e.getMessage();
                } catch (GeneralSecurityException e) {
                    result = e.getMessage();
                }
                return result;
            }

            @Override
            protected void onProgressUpdate(String... progress) {
                if (null != progress && progress.length > 0)
                    debug.setText(progress[progress.length - 1]);
            }

            @Override
            protected void onPostExecute(String result) {
                debug.setText(result);
            }
        };
        refreshTask.execute();
    }
}
