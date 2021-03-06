package net.ripe.db.whois.api.acl;

import net.ripe.db.whois.api.AbstractRestClientTest;
import net.ripe.db.whois.api.httpserver.Audience;
import net.ripe.db.whois.common.IntegrationTest;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import java.util.List;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

@Category(IntegrationTest.class)
public class AclMirrorServiceTestIntegration extends AbstractRestClientTest {
    private static final Audience AUDIENCE = Audience.INTERNAL;
    private static final String MIRRORS_PATH = "api/acl/mirrors";

    @Before
    public void setUp() throws Exception {
        databaseHelper.insertAclMirror("0/0");
        databaseHelper.insertAclMirror("10.0.0.2/32");
        databaseHelper.insertAclMirror("::0/0");
        databaseHelper.insertApiKey("DB-WHOIS-testapikey", "/api/acl", "acl api key");
        setApiKey("DB-WHOIS-testapikey");
    }

    @Test
    public void mirrors() {
        databaseHelper.insertAclMirror("10.0.0.0/32");
        databaseHelper.insertAclMirror("10.0.0.1/32");

        List<Mirror> mirrors = getMirrors();

        assertThat(mirrors, hasSize(5));
    }

    @Test
    public void getMirror_non_existing() {
        try {
            createResource(AUDIENCE, MIRRORS_PATH, "10.0.0.0/32")
                    .request(MediaType.APPLICATION_JSON)
                    .get(Mirror.class);
        } catch (NotFoundException ignored) {
            // expected
        }
    }

    @Test
    public void getMirror_existing() {
        databaseHelper.insertAclMirror("10.0.0.0/32");

        Mirror mirror = createResource(AUDIENCE, MIRRORS_PATH, "10.0.0.0/32")
                .request(MediaType.APPLICATION_JSON)
                .get(Mirror.class);

        assertThat(mirror.getPrefix(), is("10.0.0.0/32"));
    }

    @Test
    public void getMirror_invalid() {
        try {
            createResource(AUDIENCE, MIRRORS_PATH, "10")
                    .request(MediaType.APPLICATION_JSON)
                    .get(Mirror.class);
        } catch (BadRequestException e) {
            assertThat(e.getResponse().readEntity(String.class), is("'10' is not an IP string literal."));
        }
    }

    @Test
    public void createMirror() {
        Mirror mirror = createResource(AUDIENCE, MIRRORS_PATH)
                .request(MediaType.APPLICATION_JSON)
                .post(Entity.entity(new Mirror("10.0.0.0/32", "comment"), MediaType.APPLICATION_JSON), Mirror.class);

        assertThat(mirror.getPrefix(), is("10.0.0.0/32"));
        assertThat(mirror.getComment(), is("comment"));

        List<Mirror> mirrors = getMirrors();
        assertThat(mirrors, hasSize(4));
    }

    @Test
    public void createMirror_invalid() {
        try {
            createResource(AUDIENCE, MIRRORS_PATH)
                    .request(MediaType.APPLICATION_JSON)
                    .post(Entity.entity(new Mirror("10", "comment"), MediaType.APPLICATION_JSON));

        } catch (Exception e) {
            System.out.println(e.getClass());
//            assertThat(e.getResponse().readEntity(String.class), is("'10' is not an IP string literal."));
        }
    }

    @Test
    public void updateMirror() {
        Mirror mirror = createResource(AUDIENCE, MIRRORS_PATH)
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(new Mirror("10.0.0.2/32", "changed comment"), MediaType.APPLICATION_JSON), Mirror.class);

        assertThat(mirror.getPrefix(), is("10.0.0.2/32"));
        assertThat(mirror.getComment(), is("changed comment"));
        assertThat(getMirrors(), hasSize(3));
    }

    @Test
    public void deleteMirror() throws Exception {
        final Mirror mirror = createResource(AUDIENCE, MIRRORS_PATH, "10.0.0.2/32")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .delete(Mirror.class);

        assertThat(mirror.getPrefix(), is("10.0.0.2/32"));
        assertThat(getMirrors(), hasSize(2));

    }

    @SuppressWarnings("unchecked")
    private List<Mirror> getMirrors() {
        return createResource(AUDIENCE, MIRRORS_PATH)
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(new GenericType<List<Mirror>>() {});
    }
}

