package net.ripe.db.whois.update.domain;

import org.junit.Test;

import java.util.Set;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class PasswordOverrideCredentialTest {
    @Test
    public void parse_empty() {
        final PasswordOverrideCredential passwordOverrideCredential = PasswordOverrideCredential.parse("");

        assertThat(passwordOverrideCredential.toString(), is(""));

        final Set<PasswordOverrideCredential.UsernamePassword> possibleCredentials = passwordOverrideCredential.getPossibleCredentials();
        assertThat(possibleCredentials, hasSize(0));
    }

    @Test
    public void parse_one_value() {
        final PasswordOverrideCredential passwordOverrideCredential = PasswordOverrideCredential.parse("password");

        assertThat(passwordOverrideCredential.toString(), is("password"));

        final Set<PasswordOverrideCredential.UsernamePassword> possibleCredentials = passwordOverrideCredential.getPossibleCredentials();
        assertThat(possibleCredentials, containsInAnyOrder(
                new PasswordOverrideCredential.UsernamePassword("dbase1", "password"),
                new PasswordOverrideCredential.UsernamePassword("dbase2", "password")));

        assertThat(passwordOverrideCredential.getRemarks(), is(""));
    }

    @Test
    public void parse_two_values() {
        final PasswordOverrideCredential passwordOverrideCredential = PasswordOverrideCredential.parse("user,password");

        assertThat(passwordOverrideCredential.toString(), is("user,password"));

        final Set<PasswordOverrideCredential.UsernamePassword> possibleCredentials = passwordOverrideCredential.getPossibleCredentials();
        assertThat(possibleCredentials, containsInAnyOrder(
                new PasswordOverrideCredential.UsernamePassword("user", "password"),
                new PasswordOverrideCredential.UsernamePassword("dbase1", "user"),
                new PasswordOverrideCredential.UsernamePassword("dbase2", "user")));

        assertThat(passwordOverrideCredential.getRemarks(), is(""));
    }

    @Test
    public void parse_three_values() {
        final PasswordOverrideCredential passwordOverrideCredential = PasswordOverrideCredential.parse("user,password,remarks");

        assertThat(passwordOverrideCredential.toString(), is("user,password,remarks"));

        final Set<PasswordOverrideCredential.UsernamePassword> possibleCredentials = passwordOverrideCredential.getPossibleCredentials();
        assertThat(possibleCredentials, containsInAnyOrder(
                new PasswordOverrideCredential.UsernamePassword("user", "password"),
                new PasswordOverrideCredential.UsernamePassword("dbase1", "user"),
                new PasswordOverrideCredential.UsernamePassword("dbase2", "user")));

        assertThat(passwordOverrideCredential.getRemarks(), is("remarks"));
    }

    @Test
    public void parse_more_values() {
        final PasswordOverrideCredential passwordOverrideCredential = PasswordOverrideCredential.parse("user,password,remarks, and some more");

        assertThat(passwordOverrideCredential.toString(), is("user,password,remarks, and some more"));

        final Set<PasswordOverrideCredential.UsernamePassword> possibleCredentials = passwordOverrideCredential.getPossibleCredentials();
        assertThat(possibleCredentials, containsInAnyOrder(
                new PasswordOverrideCredential.UsernamePassword("user", "password"),
                new PasswordOverrideCredential.UsernamePassword("dbase1", "user"),
                new PasswordOverrideCredential.UsernamePassword("dbase2", "user")));

        assertThat(passwordOverrideCredential.getRemarks(), is("remarks, and some more"));
    }

    @Test
    public void equal() {
        final PasswordOverrideCredential passwordOverrideCredential = PasswordOverrideCredential.parse("user,password,remarks");

        assertThat(passwordOverrideCredential.equals(null), is(false));
        assertThat(passwordOverrideCredential.equals(""), is(false));
        assertThat(passwordOverrideCredential.equals(passwordOverrideCredential), is(true));
        assertThat(passwordOverrideCredential.equals(PasswordOverrideCredential.parse("user,password,remarks")), is(true));
        assertThat(passwordOverrideCredential.equals(PasswordOverrideCredential.parse("USER,password,remarks")), is(false));
    }

    @Test
    public void hash() {
        assertThat(PasswordOverrideCredential.parse("user,password,remarks").hashCode(), is(PasswordOverrideCredential.parse("user,password,remarks").hashCode()));
    }
}
