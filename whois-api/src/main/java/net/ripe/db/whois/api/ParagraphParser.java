package net.ripe.db.whois.api;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.update.domain.*;
import net.ripe.db.whois.update.keycert.PgpSignedMessage;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ParagraphParser {
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("(?im)^password:\\s*(.*)\\s*");
    private static final Pattern OVERRIDE_PATTERN = Pattern.compile("(?im)^override:\\s*(.*)\\s*");
    private static final Pattern DRY_RUN_PATTERN = Pattern.compile("(?im)^dry-run:(.*)\n*");

    private static final Splitter CONTENT_SPLITTER = Splitter.on(Pattern.compile("\\n[ \\t]*\\n")).omitEmptyStrings();

    public List<Paragraph> createParagraphs(final ContentWithCredentials contentWithCredentials, final UpdateContext updateContext) {
        String content = contentWithCredentials.getContent().replaceAll("\\r\\n", "\n");

        if (DRY_RUN_PATTERN.matcher(content).find()) {
            updateContext.dryRun();
        }

        final Set<Credential> baseCredentials = getPasswordCredentials(content);
        baseCredentials.addAll(contentWithCredentials.getCredentials());

        final List<Paragraph> paragraphs = Lists.newArrayList();

        int offset = 0;

        while (offset < content.length()) {
            final Matcher signedMessageMatcher = PgpSignedMessage.SIGNED_MESSAGE_PATTERN.matcher(content).region(offset, content.length());
            if (signedMessageMatcher.find(offset)) {
                addPlainTextContent(baseCredentials, paragraphs, content, offset, signedMessageMatcher.start());
                offset = addSignedContent(baseCredentials, paragraphs, content, signedMessageMatcher.start());
            } else {
                offset = addPlainTextContent(baseCredentials, paragraphs, content, offset, content.length());
            }
        }

        return paragraphs;
    }

    private int addPlainTextContent(final Set<Credential> baseCredentials, final List<Paragraph> paragraphs, final String content, final int beginIndex, final int endIndex) {
        if (endIndex > beginIndex) {
            final String substring = content.substring(beginIndex, endIndex);
            if (StringUtils.isNotBlank(substring)) {
                addParagraphs(paragraphs, substring, baseCredentials);
            }
        }
        return endIndex + 1;
    }

    private int addSignedContent(final Set<Credential> baseCredentials, final List<Paragraph> paragraphs, final String content, final int beginIndex) {
        final Set<Credential> credentials = Sets.newLinkedHashSet(baseCredentials);

        int endIdx = -1;
        String signedContent = content.substring(beginIndex);

        while (true) {
            final Matcher matcher = PgpSignedMessage.SIGNED_MESSAGE_PATTERN.matcher(signedContent);
            if (matcher.find()) {
                if (endIdx == -1) {
                    endIdx = beginIndex + matcher.end() + 1;
                }

                try {
                    final String clearText = matcher.group(0);
                    final PgpCredential credential = PgpCredential.createOfferedCredential(clearText);
                    credentials.add(credential);
                    signedContent = credential.getContent();
                    if (StringUtils.isBlank(signedContent)) {
                        addPlainTextContent(baseCredentials, paragraphs, clearText, 0, clearText.length());
                    }
                } catch (IllegalArgumentException e) {
                    addPlainTextContent(baseCredentials, paragraphs, signedContent, 0, signedContent.length());
                }
            } else {
                addParagraphs(paragraphs, signedContent, credentials);
                break;
            }
        }
        return endIdx == -1 ? content.length() : endIdx;
    }

    private Set<Credential> getPasswordCredentials(final String content) {
        final Set<Credential> result = Sets.newLinkedHashSet();

        final Matcher matcher = PASSWORD_PATTERN.matcher(content);
        while (matcher.find()) {
            result.add(new PasswordCredential(matcher.group(1).trim()));
        }

        return result;
    }

    private Matcher isThisParagraphADomainToSplit(String paragraph) {
        Matcher matcher = Domain.DOMAIN_DASH_3_PATTERN.matcher(paragraph);
        if(!matcher.find()) {
            matcher = Domain.DOMAIN_DASH_2_PATTERN.matcher(paragraph);
            if(!matcher.find()) {
                matcher = Domain.DOMAIN_DASH_1_PATTERN.matcher(paragraph);
                if(!matcher.find()) {
                    return null;
                }
            }
        }
        return matcher;
    }

    private Collection<? extends Paragraph> splitDomainIntoMultipleParagraphs(String cleanedParagraph, Set<Credential> credentials, Matcher matcher) {
        List<Paragraph> paragraphs = new ArrayList<Paragraph>();
        String domainValue = matcher.group("domainValue");

        List<String> splittedDomainValues = (new SplitDomainWithDashNotation()).split(domainValue);
        for (String domain : splittedDomainValues) {
            // add the generated attribute
            String newSplittedDomainValue = domain + "\n" + AttributeType.FROM_DASH_NOTATION.getName() + ": true";

            String newParagraph = cleanedParagraph.replaceFirst(domainValue, newSplittedDomainValue);
            paragraphs.add(new Paragraph(newParagraph, new Credentials(credentials)));
        }
        return paragraphs;
    }

    private void addParagraphs(final List<Paragraph> paragraphs, final String content, final Set<Credential> baseCredentials) {
        for (final String paragraph : CONTENT_SPLITTER.split(content)) {
            if (StringUtils.isNotEmpty(paragraph)) {
                final Set<Credential> credentials = Sets.newLinkedHashSet(baseCredentials);

                String cleanedParagraph = paragraph;

                cleanedParagraph = removePasswords(cleanedParagraph);
                cleanedParagraph = removeDryRun(cleanedParagraph);
                cleanedParagraph = extractOverride(credentials, cleanedParagraph);
                cleanedParagraph = cleanedParagraph.trim();

                Matcher matcher = isThisParagraphADomainToSplit(cleanedParagraph);

                if (matcher == null) {
                    // Also add empty paragraphs to detect dangling credentials
                    paragraphs.add(new Paragraph(cleanedParagraph, new Credentials(credentials)));
                } else {
                    paragraphs.addAll(splitDomainIntoMultipleParagraphs(cleanedParagraph, credentials, matcher));
                }
            }
        }
    }

    private String removePasswords(final String paragraph) {
        return PASSWORD_PATTERN.matcher(paragraph).replaceAll("");
    }

    private String removeDryRun(final String paragraph) {
        return DRY_RUN_PATTERN.matcher(paragraph).replaceAll("");
    }

    private String extractOverride(final Set<Credential> credentials, final String paragraph) {
        final Matcher overrideMatcher = OVERRIDE_PATTERN.matcher(paragraph);
        while (overrideMatcher.find()) {
            credentials.add(PasswordOverrideCredential.parse(overrideMatcher.group(1).trim()));
        }

        return overrideMatcher.reset().replaceAll("");
    }

    private class SplitDomainWithDashNotation {
        public List<String> split(String domainValue) {
            List<String> splitDomains = null;

            int indexOfFirstDot = domainValue.indexOf('.');
            int indexOfDash = domainValue.indexOf('-');

            if (indexOfDash < indexOfFirstDot) {
                int intervalStart = Integer.valueOf(domainValue.substring(0, indexOfDash));
                int intervalEnd = Integer.valueOf(domainValue.substring(indexOfDash + 1, indexOfFirstDot));

                if (intervalEnd >= intervalStart) {
                    splitDomains = new ArrayList<String>();

                    for (int i = intervalStart; i <= intervalEnd; i++) {
                        String newDomainValue = i + domainValue.substring(indexOfFirstDot);
                        splitDomains.add(newDomainValue);
                    }
                }
            }
            return splitDomains;
        }
    }
}
