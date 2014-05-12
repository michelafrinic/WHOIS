package net.ripe.db.whois.common.rpsl.transform;

import net.ripe.db.whois.common.rpsl.RpslObject;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class FilterAuthFunctionTest {
    FilterAuthFunction subject;

    @Before
    public void setUp() throws Exception {
        subject = new FilterAuthFunction();
    }

    @Test
    public void apply_irt() {
        final RpslObject rpslObject = RpslObject.parse("" +
                "irt: DEV-IRT\n" +
                "auth: MD5-PW $1$YmPozTxJ$s3eGZRVrKVGdSDTeEZJu\n" +
                "source: RIPE"
        );

        final RpslObject response = subject.apply(rpslObject);
        assertThat(response, is(RpslObject.parse("" +
                "irt:            DEV-IRT\n" +
                "auth:           MD5-PW # Filtered\n" +
                "source:         RIPE # Filtered\n")));
    }

    @Test
    public void apply_no_md5() {
        final RpslObject rpslObject = RpslObject.parse("" +
                "mntner: WEIRD-MNT\n" +
                "auth: value\n" +
                "source: RIPE"
        );

        final RpslObject response = subject.apply(rpslObject);
        assertThat(response, is(rpslObject));
    }

    @Test
    public void apply_md5() {
        final RpslObject rpslObject = RpslObject.parse("" +
                "mntner: WEIRD-MNT\n" +
                "auth: MD5-PW $1$YmPozTxJ$s3eGZRVrKVGdSDTeEZJu//\n" +
                "auth: MD5-PW $1$YmPozTxJ$s3eGZRVrKVGdSDTeEZJu//\n" +
                "source: RIPE"
        );

        final RpslObject response = subject.apply(rpslObject);

        assertThat(response.toString(), is("" +
                "mntner:         WEIRD-MNT\n" +
                "auth:           MD5-PW # Filtered\n" +
                "auth:           MD5-PW # Filtered\n" +
                "source:         RIPE # Filtered\n"));
    }

    @Test
    public void apply_crypt() {
        final RpslObject rpslObject = RpslObject.parse("" +
                "mntner: WEIRD-MNT\n" +
                "auth: CRYPT-PW apGl30xzHaZxE\n" +
                "auth: CRYPT-PW apGl30xzHaZxE\n" +
                "source: RIPE"
        );

        final RpslObject response = subject.apply(rpslObject);

        assertThat(response.toString(), is("" +
                "mntner:         WEIRD-MNT\n" +
                "auth:           CRYPT-PW # Filtered\n" +
                "auth:           CRYPT-PW # Filtered\n" +
                "source:         RIPE # Filtered\n"));
    }
}
