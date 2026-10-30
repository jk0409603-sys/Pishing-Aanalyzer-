#ifndef JSON_BUILDER_H   // Check if JSON_BUILDER_H is not defined
#define JSON_BUILDER_H  // Define JSON_BUILDER_H

#include <string>        // Include the string library
#include <vector>        // Include the vector library
using namespace std;     // Use the standard namespace

struct URLFEATURES       // Define a structure to hold URL features
{
  bool https;
  int length;
  int dots;
  int subdomain;
  bool isIPHOST;
  bool hasSpecialchar;
};

string buildJSON(URLFEATURES f, vector<string> indicators, string risk)  //creating json from the features and indicators and risk
{
    string json = "{\n";           // Start building the JSON string
    json += "  \"risk\": \"" + risk + "\",\n";
    json += "  \"features\": {\n";     // Add the features to the JSON string
    json += "    \"https\": " + string(f.https ? "true" : "false") + ",\n";
    json += "    \"length\": " + to_string(f.length) + ",\n";
    json += "    \"dots\": " + to_string(f.dots) + ",\n";
    json += "    \"subdomains\": " + to_string(f.subdomain) + ",\n";
    json += "    \"isIPHost\": " + string(f.isIPHOST ? "true" : "false") + ",\n";
    json += "    \"hasSpecialChars\": " + string(f.hasSpecialchar ? "true" : "false") + "\n";
    json += "  },\n";
    json += "  \"indicators\": [";         // Add the indicators to the JSON string
    for (int i = 0; i < indicators.size(); i++) {
        json += "\"" + indicators[i] + "\"";
        if (i != indicators.size() - 1) json += ", ";
    }
    json += "]\n";
    json += "}";
    return json;
}

#endif