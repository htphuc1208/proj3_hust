package org.example;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
public class App { public static void main(String[] args) {
 System.out.println(new ArchiveStreamFactory().getEntryEncoding());
} }
