package net.afrinic.db.rules;

import net.ripe.db.whois.common.rpsl.AttributeTemplate;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.drools.KnowledgeBase;
import org.drools.KnowledgeBaseFactory;
import org.drools.builder.KnowledgeBuilder;
import org.drools.builder.KnowledgeBuilderFactory;
import org.drools.builder.ResourceType;
import org.drools.definition.KnowledgePackage;
import org.drools.definition.rule.Rule;
import org.drools.io.ResourceFactory;
import org.drools.runtime.StatefulKnowledgeSession;
import org.junit.Assert;
import org.junit.Test;

import static net.ripe.db.whois.common.rpsl.AttributeType.*;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Requirement.*;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Cardinality.*;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Key.*;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Iterator;

/**
 * Created by michel on 4/7/14.
 */
public class DroolsTest {
    private static KnowledgeBase createKnowledgeBase() {
        KnowledgeBuilder builder = KnowledgeBuilderFactory.newKnowledgeBuilder();

        //Add drl file into builder
        String resourceName = "afrinic.drl";
        URL fileURL = Thread.currentThread().getContextClassLoader().getResource(resourceName);
        File drl = null;
        try {
            drl = new File(fileURL.toURI());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        builder.add(ResourceFactory.newFileResource(drl), ResourceType.DRL);
        if (builder.hasErrors()) {
            throw new RuntimeException(builder.getErrors().toString());
        }

        KnowledgeBase knowledgeBase = KnowledgeBaseFactory.newKnowledgeBase();
        //Add to Knowledge Base packages from the builder which are actually the rules from the drl file.
        knowledgeBase.addKnowledgePackages(builder.getKnowledgePackages());

        return knowledgeBase;
    }

    @Test
    public void test() {
        //Create KnowledgeBase...
        KnowledgeBase knowledgeBase = createKnowledgeBase();
        //Create a stateful session
        StatefulKnowledgeSession session = knowledgeBase.newStatefulKnowledgeSession();
        try {

            //Create Facts and insert them
            ObjectTemplate objectTemplatePerson = new ObjectTemplate();
            objectTemplatePerson.setObjectType(ObjectType.PERSON);

            objectTemplatePerson.setAttributeTemplates(new AttributeTemplate(PERSON, MANDATORY, SINGLE, LOOKUP_KEY),
                    new AttributeTemplate(ADDRESS, MANDATORY, MULTIPLE),
                    new AttributeTemplate(PHONE, MANDATORY, MULTIPLE),
                    new AttributeTemplate(FAX_NO, OPTIONAL, MULTIPLE),
                    new AttributeTemplate(ORG, OPTIONAL, MULTIPLE, INVERSE_KEY),
                    new AttributeTemplate(NIC_HDL, MANDATORY, SINGLE, PRIMARY_KEY, LOOKUP_KEY),
                    new AttributeTemplate(REMARKS, OPTIONAL, MULTIPLE),
                    new AttributeTemplate(NOTIFY, OPTIONAL, MULTIPLE, INVERSE_KEY),
                    new AttributeTemplate(ABUSE_MAILBOX, OPTIONAL, MULTIPLE, INVERSE_KEY),
                    new AttributeTemplate(CHANGED, MANDATORY, MULTIPLE),
                    new AttributeTemplate(SOURCE, MANDATORY, SINGLE));

            session.insert(objectTemplatePerson);
            //session.fireAllRules();

            AttributeTemplate email = objectTemplatePerson.getAttributeTemplate(E_MAIL);
            AttributeTemplate mntBy = objectTemplatePerson.getAttributeTemplate(MNT_BY);

            Assert.assertNotNull(email);
            Assert.assertNotNull(mntBy);

            Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, email.getRequirement());
            Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, mntBy.getRequirement());

        } finally {
            session.dispose();
        }
    }

}
