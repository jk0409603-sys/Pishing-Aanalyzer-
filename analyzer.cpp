#include<iostream>
#include<string>
#include<sstream>
#include<vector>
#include "json_builder.h"
using namespace std;

//feature 1: check the protocol is https or not
bool hasHTTPS(string protocol) //check protocoll
{
    return protocol=="https";
}

//feature 2 :how log url was 
int urllength(string url)
{
    return url.length();
}

//feature no 3: dots in domain 
int countdots(string domain)
{
    int count=0;
 if(domain[i]=='.')
 {
    count++;
 }
 return count; 
}

//feature no 4 check domain is ip or not 
bool isIPHOST(string domain)
{
    for(int i=0;i<domain.size();i++)
    {
        if((domain[i]>='0'&& domain[i]<='9')|| domain[i]=='.')
        {
            continue;
        }
        else
        {
            return false;
        }

    }
    return true;
}

//feature no 6: check is it has special charater or not
bool hasspecialChar(string url)
{
    for(int i=0;i<url.size();i++)
    {
        if((url[i]>='a' && url[i]<='z')||(url[i]<='A'&& url[i]<='Z')||(url[i]<='0'&& url[i]>='9')||url[i] == '.' || url[i] == '-' ||
            url[i] == ':' || url[i] == '/' ||
            url[i] == '?' || url[i] == '=' ||
            url[i] == '&')
            {
                continue;
            }
            else
            {
                return true;
            }
    }
    return false;
}



//function to get indicator base on url 
vector<string> getIndicators(URLFEATURES F)
{
    vector<string> indicator;
    if(!F.https)
    {
        indicator.push_back("No HTTPS");
    }
    if(F.isIPHOST)
    {
        indicator.push_back("IP address used as host");
    }
    if(F.length>75)
    {
        indicator.push_back("Unusually long url ")
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