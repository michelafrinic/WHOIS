package net.afrinic.db.rules;

import net.ripe.db.whois.common.rpsl.AttributeTemplate;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by yogesh on 4/4/14.
 */
@RunWith(MockitoJUnitRunner.class)
public class RulesTest {

    private final WhoisRules whr = new WhoisRules();

    @Test
    public void printRpsl() {

        ObjectTemplate[] objectTemplates = buildObjectTree();

        for (ObjectTemplate objectTemplate: objectTemplates) {
            System.out.println();
            System.out.println(objectTemplate);
        }

    }

    @Test
    public void afrinicPerson() {
        AttributeTemplate personEmail = null;
        AttributeTemplate personMntBy = null;

        AttributeTemplate[] attributeTemplates = whr.getAttributeTemplates();


        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            if (ObjectType.PERSON.equals(attributeTemplate.getObjectType()))  {
                if (AttributeType.E_MAIL.equals(attributeTemplate.getAttributeType())) {
                    personEmail = attributeTemplate;

                } else if (AttributeType.MNT_BY.equals(attributeTemplate.getAttributeType())) {
                    personMntBy = attributeTemplate;
                }
            }
        }
        Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, personEmail.getRequirement());
        Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, personMntBy.getRequirement());
    }

    @Test
    public void ripePerson() {
        AttributeTemplate personEmail = null;
        AttributeTemplate personMntBy = null;

        AttributeTemplate[] attributeTemplates = whr.getAttributeTemplates();


        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            if (ObjectType.PERSON.equals(attributeTemplate.getObjectType()))  {
                if (AttributeType.E_MAIL.equals(attributeTemplate.getAttributeType())) {
                    personEmail = attributeTemplate;

                } else if (AttributeType.MNT_BY.equals(attributeTemplate.getAttributeType())) {
                    personMntBy = attributeTemplate;
                }
            }
        }
        Assert.assertEquals(AttributeTemplate.Requirement.OPTIONAL, personEmail.getRequirement());
        Assert.assertEquals(AttributeTemplate.Requirement.MANDATORY, personMntBy.getRequirement());
    }

    private ObjectTemplate[] buildObjectTree() {

        Map<ObjectType,Set<AttributeTemplate>> mapA = new HashMap<>();

        AttributeTemplate[] attributeTemplates = whr.getAttributeTemplates();
        for (AttributeTemplate attributeTemplate: attributeTemplates) {
            ObjectType objectType = attributeTemplate.getObjectType();
            if (!mapA.containsKey(objectType))  {
                mapA.put(objectType, new LinkedHashSet<AttributeTemplate>());
            }
            mapA.get(objectType).add(attributeTemplate);

            System.out.println(attributeTemplate);
        }

        ObjectTemplate[] objectTemplates = whr.getObjectTemplates();
        for (ObjectTemplate objectTemplate: objectTemplates) {
            ObjectType objectType =  objectTemplate.getObjectType();
            if (mapA.containsKey(objectType)) {
                objectTemplate.setAttributeTemplates(mapA.get(objectType).toArray(new AttributeTemplate[0]));
            }
        }

        return objectTemplates;
    }


    // TODO replace the whole PERSON object definition in ObjectTemplate


    /*
    @Test
    public void test1() {
        ObjectMapper om = new ObjectMapper();
        try {
            AttributeTemplate t = om.readValue(
                    "{\"attributeType\":\"CHANGED\", " +
                            "\"requirement\": \"OPTIONAL\", " +
                            "\"cardinality\":\"MULTIPLE\", " +
                            "\"keys\": [\"PRIMARY_KEY\", \"LOOKUP_KEY\"]}", AttributeTemplate.class);
            System.out.println();
            System.out.println(t);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    */

    /*
    @Test
    public void test2() {
        ObjectMapper om = new ObjectMapper();
        try {
            ObjectTemplate t = om.readValue(
                    "{\"objectType\": \"ROUTE\", " +
                        "\"orderPosition\": 10, " +
                        "\"attributeTemplates\": ["+
                          "{\"attributeType\":\"ROUTE\", " +
                          "\"requirement\": \"MANDATORY\", " +
                          "\"cardinality\":\"SINGLE\", " +
                          "\"keys\": [\"PRIMARY_KEY\", \"LOOKUP_KEY\"]" +
                          "}," +
                          "{\"attributeType\":\"CHANGED\", " +
                            "\"requirement\": \"OPTIONAL\", " +
                            "\"cardinality\":\"MULTIPLE\", " +
                            "\"keys\": [\"PRIMARY_KEY\", \"LOOKUP_KEY\"]" +
                          "}" +
                        "]" +
                    "}", ObjectTemplate.class);
            System.out.println();
            System.out.println(t);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    */
}
