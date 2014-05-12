package net.ripe.db.ascleanup;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.mysql.jdbc.Driver;
import net.ripe.db.whois.common.ClockDateTimeProvider;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.Messages;
import net.ripe.db.whois.common.dao.jdbc.JdbcStreamingHelper;
import net.ripe.db.whois.common.dao.jdbc.domain.ObjectTypeIds;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceLoader;
import net.ripe.db.whois.common.io.Downloader;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.ResponseMessage;
import net.ripe.db.whois.update.log.LoggerContext;
import net.ripe.db.whois.update.mail.MailGateway;
import net.ripe.db.whois.update.mail.MailMessageLogCallback;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.PatternLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.sql.DataSource;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutNumCleanup {
    private static final Logger LOGGER = LoggerFactory.getLogger("AutNumCleanup");
    private static final Pattern AS_PATTERN = Pattern.compile("(?i)(?<![\\w:])(AS\\d+)(?![\\w:])");
    private static final List<AttributeType> ATTRIBUTES_TO_CHECK = Lists.newArrayList(
            AttributeType.IMPORT,
            AttributeType.EXPORT,
            AttributeType.MP_IMPORT,
            AttributeType.MP_EXPORT,
            AttributeType.DEFAULT,
            AttributeType.MP_DEFAULT,
            AttributeType.AGGR_BNDRY,
            AttributeType.AGGR_MTD,
            AttributeType.COMPONENTS,
            AttributeType.EXPORT_COMPS,
            AttributeType.FILTER,
            AttributeType.MP_FILTER,
            AttributeType.IFADDR,
            AttributeType.INTERFACE,
            AttributeType.INJECT,
            AttributeType.LOCAL_AS,
            AttributeType.MP_MEMBERS,
            AttributeType.MEMBERS,
            AttributeType.PEER,
            AttributeType.PEERING,
            AttributeType.MP_PEER,
            AttributeType.MP_PEERING,
            AttributeType.ORIGIN
    );


    private static final String MAIL_HOST = "massmailer.afrinic.net";
    private static final int MAIL_PORT = 25;
    private static final String LOG_DIR = "var";
    private static final Joiner JOINER = Joiner.on(',');
    private final MailGateway mailGateway;


    public static void main(String[] argv) throws Exception {
        setupLogging();

        new AutNumCleanup().execute(argv[0]);
    }

    private static void setupLogging() {
        LogManager.getRootLogger().setLevel(Level.INFO);
        ConsoleAppender console = new ConsoleAppender();
        console.setLayout(new PatternLayout("%d [%c|%C{1}] %m%n"));
        console.setThreshold(Level.INFO);
        console.activateOptions();
        LogManager.getRootLogger().addAppender(console);
    }

    public AutNumCleanup() {
        this.mailGateway = createMailGateway();
    }

    private MailGateway createMailGateway() {
        final JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setPort(MAIL_PORT);
        mailSender.setHost(MAIL_HOST);

        final LoggerContext loggerContext = new LoggerContext(new ClockDateTimeProvider());
        loggerContext.setBaseDir(LOG_DIR);
        loggerContext.init("AUTNUMCLEANUP");

        return new MailGatewayImpl(mailSender, loggerContext);
    }

    public void execute(final String mysqlConnectionPassword) throws Exception {
        final Path resourceDataFile = Files.createTempFile("autnumCleanup", "");

        final Downloader downloader = new Downloader();

        downloader.downloadToWithMd5Check(LOGGER, new URL("ftp://ftp.afrinic.net/afrinic/stats/delegated-afrinic-extended-latest"), resourceDataFile);

        final AuthoritativeResourceLoader authoritativeResourceLoader = new AuthoritativeResourceLoader(LOGGER, "ripe", new Scanner(resourceDataFile), Sets.newHashSet("reserved"));
        final AuthoritativeResource authoritativeResource = authoritativeResourceLoader.load();

        final DataSource dataSource = new SimpleDriverDataSource(new Driver(), "jdbc:mysql://db.afrinic.net/WHOIS_UPDATE", "rdonly", mysqlConnectionPassword);
        final JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);

        LOGGER.info("There are " + authoritativeResource.getNrAutNums() + " reserved autnums");

        sendMails(jdbcTemplate, findAutnumReferencesPerObject(jdbcTemplate, authoritativeResource));
    }

    private Map<RpslObject, Set<String>> findAutnumReferencesPerObject(final JdbcTemplate jdbcTemplate, final AuthoritativeResource authoritativeResource) {
        final Map<RpslObject, Set<String>> referencedAutnumsPerObject = Maps.newHashMap();
        JdbcStreamingHelper.executeStreaming(jdbcTemplate,
                "SELECT object_id, object " +
                        "FROM last " +
                        "WHERE sequence_id != 0 " +
                        "AND object_type NOT IN (100," +
                        // quick win filter to reduce data size by >80%
                        JOINER.join(
                                ObjectTypeIds.getId(ObjectType.PERSON),
                                ObjectTypeIds.getId(ObjectType.ROLE),
                                ObjectTypeIds.getId(ObjectType.INETNUM),
                                ObjectTypeIds.getId(ObjectType.INET6NUM),
                                ObjectTypeIds.getId(ObjectType.DOMAIN)
                        ) + ")",
                new RowCallbackHandler() {
                    @Override
                    public void processRow(final ResultSet rs) throws SQLException {
                        final int objectId = rs.getInt(1);
                        RpslObject object = null;
                        try {
                            object = RpslObject.parse(objectId, rs.getBytes(2));
                        } catch (RuntimeException e) {
                            LOGGER.warn("Unable to parse RPSL object with object_id: {}", objectId);
                        }

                        if (object == null) {
                            return;
                        }

                        final Set<String> foundAutnums = Sets.newHashSet();

                        for (final RpslAttribute attribute : object.findAttributes(ATTRIBUTES_TO_CHECK)) {
                            for (final CIString value : attribute.getCleanValues()) {
                                final Matcher matcher = AS_PATTERN.matcher(value.toString());
                                while (matcher.find()) {
                                    final String match = matcher.group();
                                    if (authoritativeResource.isMaintainedByRir(ObjectType.AUT_NUM, CIString.ciString(match))) {
                                        foundAutnums.add(match);
                                    }
                                }
                            }
                        }

                        if (!foundAutnums.isEmpty()) {
                            if (referencedAutnumsPerObject.get(object) == null) {
                                referencedAutnumsPerObject.put(object, foundAutnums);
                            } else {
                                referencedAutnumsPerObject.get(object).addAll(foundAutnums);
                            }
                        }
                    }
                });
        return referencedAutnumsPerObject;
    }

    private void sendMails(final JdbcTemplate jdbcTemplate, final Map<RpslObject, Set<String>> referencedAutnumsPerObject) {
        final Map<CIString, List<Container>> cleanupsPerMntnerEmail = Maps.newHashMap();

        for (final RpslObject rpslObject : referencedAutnumsPerObject.keySet()) {
            if (!referencedAutnumsPerObject.get(rpslObject).isEmpty()) {
                final Set<CIString> mntners = Sets.newHashSet();
                JdbcStreamingHelper.executeStreaming(jdbcTemplate,
                        "SELECT object_id, object" +
                                " FROM last" +
                                " WHERE sequence_id != 0" +
                                " AND object_type = " + ObjectTypeIds.getId(ObjectType.MNTNER) +
                                " AND pkey in ('" + JOINER.join(rpslObject.getValuesForAttribute(AttributeType.MNT_BY)) + "')",
                        new RowCallbackHandler() {
                            @Override
                            public void processRow(final ResultSet rs) throws SQLException {
                                final int objectId = rs.getInt(1);
                                try {
                                    mntners.addAll(RpslObject.parse(objectId, rs.getBytes(2)).getValuesForAttribute(AttributeType.UPD_TO));
                                } catch (RuntimeException e) {
                                    LOGGER.warn("Unable to parse RPSL object with object_id: {}", objectId);
                                }
                            }
                        });

                for (final CIString email : mntners) {
                    if (cleanupsPerMntnerEmail.get(email) == null || cleanupsPerMntnerEmail.get(email).isEmpty()) {
                        cleanupsPerMntnerEmail.put(email, Lists.newArrayList(new Container(rpslObject, referencedAutnumsPerObject.get(rpslObject))));
                    } else {
                        cleanupsPerMntnerEmail.get(email).add(new Container(rpslObject, referencedAutnumsPerObject.get(rpslObject)));
                    }
                }
            }
        }

        LOGGER.info("About to send {} emails", cleanupsPerMntnerEmail.size());

        for (final CIString email : cleanupsPerMntnerEmail.keySet()) {
            mailGateway.sendEmail(email.toString(), "Clean up of old ASN references in the Whois Database", createMailContent(cleanupsPerMntnerEmail.get(email)));
            LOGGER.info("Mailing {}, content: {}", email, createMailContent(cleanupsPerMntnerEmail.get(email)));
        }
    }

    private String createMailContent(final List<Container> containers) {
        final StringBuilder builder = new StringBuilder();
        builder.append("Dear Colleagues,\n\n")
                .append("The registry is sending you this email as some of your objects in the database still reference deleted AS Numbers.")
                .append("Before these AS Numbers can be re-assigned all references to them need to be removed.")
                .append("Below is a list of your objects that have these references.")
                .append("Please update your objects to remove these references.\n\n")
                .append("IMPORTANT: If you have any scripts or templates to auto-generate any of these objects, please also adjust them to prevent these references being re-generated.\n\n")
                .append("Your Object:\t\treferences these deleted AS Numbers\n\n");
        for (final Container container : containers) {
            builder.append(container.getObjectWithAutnumReferences().getKey())
                    .append("\t\t")
                    .append(JOINER.join(container.getAutnumsFoundInObject()))
                    .append("\n");
        }

        builder.append("\nIf you have any questions or need help to remove the references please contact our Customer Services afrinic-dbm@afrinic.net\n\n")
                .append("Regards\n" +
                        "Database Team");
        return builder.toString();
    }

    private class Container {
        private RpslObject objectWithAutnumReferences;
        private Set<String> autnumsFoundInObject;

        public Container(final RpslObject object, final Set<String> autnums) {
            this.objectWithAutnumReferences = object;
            this.autnumsFoundInObject = autnums;
        }

        private RpslObject getObjectWithAutnumReferences() {
            return objectWithAutnumReferences;
        }

        private Set<String> getAutnumsFoundInObject() {
            return autnumsFoundInObject;
        }
    }

    private class MailGatewayImpl implements MailGateway {
        private static final String MAIL_FROM = "Database Administration <no-reply@afrinic.net>";
        private static final String MAIL_REPLY_TO = "no-reply@afrinic.net";

        private final JavaMailSender mailSender;
        private final LoggerContext loggerContext;

        private MailGatewayImpl(final JavaMailSender mailSender, final LoggerContext loggerContext) {
            this.mailSender = mailSender;
            this.loggerContext = loggerContext;
        }

        @Override
        public void sendEmail(String to, ResponseMessage responseMessage) {
            throw new UnsupportedOperationException("not supported");
        }

        @Override
        public void sendEmail(final String to, final String subject, final String text) {
            try {
                mailSender.send(new MimeMessagePreparator() {
                    @Override
                    public void prepare(final MimeMessage mimeMessage) throws MessagingException {
                        final MimeMessageHelper message = new MimeMessageHelper(mimeMessage, MimeMessageHelper.MULTIPART_MODE_NO, "UTF-8");
                        message.setFrom(MAIL_FROM);
                        message.setTo(to);
                        message.setReplyTo(MAIL_REPLY_TO);
                        message.setSubject(subject);
                        message.setText(text);

                        mimeMessage.addHeader("Precedence", "bulk");
                        mimeMessage.addHeader("Auto-Submitted", "auto-generated");

                        loggerContext.log("msg-out.txt", new MailMessageLogCallback(mimeMessage));
                    }
                });
            } catch (MailException e) {
                loggerContext.log(new Message(Messages.Type.ERROR, "Unable to send mail to {} with subject {}", to, subject), e);
                LOGGER.error("Unable to send mail message to: {}", to, e);
            }
        }
    }
}
