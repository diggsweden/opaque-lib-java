package se.digg.crypto.opaque.testdata;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * TestVectorData for OPRF test vectors
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OPRFTestVectorData {

  String groupDST, hash, identifier, keyInfo, seed, skSm;
  int mode;

  List<OPRFTestVectors> vectors;



  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OPRFTestVectors{

    @JsonProperty("Batch")
    int batch;
    @JsonProperty("Blind")
    String blind;
    @JsonProperty("BlindedElement")
    String blindedElement;
    @JsonProperty("EvaluationElement")
    String evaluationElement;
    @JsonProperty("Input")
    String input;
    @JsonProperty("Output")
    String output;
    @JsonProperty("Proof")
    OPRFProof proof;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class OPRFProof {

    String proof;
    String r;

  }

}
