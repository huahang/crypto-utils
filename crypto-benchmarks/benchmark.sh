#!/usr/bin/env bash
mvn clean package exec:java -Dexec.mainClass="im.chic.utils.crypto.benchmarks.Benchmark"
