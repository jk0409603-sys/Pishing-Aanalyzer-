#include<iostream>
#include<string>
#include<sstream>
#include<vector>
#include "json_builder.h"
using namespace std;

//create a structure to store the url information
struct URLFEATURES
{
  bool https; //check the protocol is https or not
  int length; //check the length of the url
  int dots; //check how many dots are in the domain
  int subdomain; //check how many subdomains are in the domain
  bool isIPHOST; //check the domain is ip or not
  bool hasSpecialchar; //check the domain has special character or not
};

//feature 4: how many subdomains are in the domain
int countsubdomains(int dots) //check how many subdomains are in the domain
{
  int subs=dots-1;
  if(subs<0)
    subs=0;
  return subs;
}

//feature 5: check the domain is ip or not
bool isIPHOST(string domain) //check the domain is ip or not
{
  for(int i=0;i<domain.size();i++)
  {
    if((domain[i]>='0' && domain[i]<='9') || domain[i]=='.')
      continue;
    else
      return false;
  }
  return true;
}


//feature 6: check the domain has special character or not
bool hasSpecialChar(string url) // check the URL has special character or not
{
    for (int i = 0; i < url.size(); i++)
    {
        if ((url[i] >= 'a' && url[i] <= 'z') ||
            (url[i] >= 'A' && url[i] <= 'Z') ||
            (url[i] >= '0' && url[i] <= '9') ||
            url[i] == '.' || url[i] == '-' ||
            url[i] == ':' || url[i] == '/' ||
            url[i] == '?' || url[i] == '=' ||
            url[i] == '&')
            continue;
        else
            return true;
    }
    return false;
}




// use functions 
//feature 1 : check the protocol is https or not
bool hasHTTPS(string protocol)  //check the protocol is https or not
{
  return protocol=="https";
}
//feature 2: how long url is be 

int urllengtH(string url) //check the length of the url
{
  return url.length();
}

//feature 3: how many dots are in the domain
int countdots(string domain)
{
  int coount=0;
  for(int i=0;i<domain.size();i++)
  {
    if(domain[i]=='.')
      coount++;
  }
  return coount;
}


vector<string> getIndicators(URLFEATURES F) {
    vector<string> indicators;

    if (!F.https) {
        indicators.push_back("No HTTPS");
    }
    if (F.isIPHOST) {
        indicators.push_back("IP address used as host");
    }
    if (F.length > 75) {
        indicators.push_back("Unusually long URL");
    }
    if (F.subdomain > 2) {
        indicators.push_back("Too many subdomains");
    }
    if (F.hasSpecialchar) {
        indicators.push_back("Suspicious special characters");
    }

    return indicators;
}

string getRiskLevel(vector<string> indicators) {
    int count = indicators.size();
    if (count == 0) return "LOW CONCERN";
    else if (count <= 2) return "MEDIUM CONCERN";
    else return "HIGHER CONCERN";
}

 int main()
 {
    string url;
    cout<<"Enter the URL :";
    cin>>url;

    //step 1  check the ://;
    size_t protocolEnd=url.find("://");
    string protocol="";
    string rest =url; //after remove protocol of https 

    if(protocolEnd!=string::npos)
    {
      protocol=url.substr(0,protocolEnd);
      rest=url.substr(protocolEnd+3); //remove the :// from the url
    }

    //saperate domain from path
    size_t pathstart=rest.find("/");
    string domain=rest;
    string path="";

    if(pathstart!=string::npos)
    {
      domain=rest.substr(0,pathstart);
      path=rest.substr(pathstart); //get the path after the domain
    }
    cout<<"You Entered : "<<url<<endl;
    cout<<"Protocol : "<<protocol<<endl;
    cout<<"Domain : "<<domain<<endl;
    cout<<"Path : "<<path<<endl;

   //print result of all features ;

    cout<<"HTTPS :"<<(hasHTTPS(protocol) ? "Yes" : "No")<<endl;
    cout<<"URL Length : "<<urllengtH(url)<<endl;
    cout<<"Dots in Domain : "<<countdots(domain)<<endl;
    cout<<"Subdomains in Domain : "<<countsubdomains(countdots(domain))<<endl;
    cout<<"Is IP Host : "<<(isIPHOST(domain) ? "Yes" : "No")<<endl;
    cout<<"Has Special Character : "<<(hasSpecialChar(url) ? "Yes" : "No")<<endl;
    
    URLFEATURES F;
    F.https = hasHTTPS(protocol); 
    F.length = urllengtH(url);
    F.dots = countdots(domain);
    F.subdomain = countsubdomains(F.dots);
    F.isIPHOST = isIPHOST(domain);
    F.hasSpecialchar = hasSpecialChar(url);

     // NOW build indicators and risk, using the completed struct
    vector<string> indicators = getIndicators(F);
    string risk = getRiskLevel(indicators);

    // NOW build the JSON, since F, indicators, and risk all exist
    string json = buildJSON({F.https, F.length, F.dots, F.subdomain,
                 F.isIPHOST, F.hasSpecialchar}, indicators, risk);
    cout << "\n--- JSON Output ---\n" << json << endl;
    
    return 0;
 }