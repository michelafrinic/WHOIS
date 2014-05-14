package net.ripe.db.whois.update.domain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Created by avinash on 5/12/14.
 */
public class PgpOverrideCredential implements OverrideCredential{

    private PgpCredential pgpOverrideCredentials;

    public PgpOverrideCredential(PgpCredential pgpOverrideCredential) {
        this.pgpOverrideCredentials = pgpOverrideCredential;
    }

}
