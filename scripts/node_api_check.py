#!/usr/bin/python3

import requests as r
import argparse
import sys
import pandas as pd
import json

class MainFunctions:

    def __init__(self):
        self.api_url = "https://validator.nymtech.net/api/v1"
        #self.api_existing_endpoints_url = "https://validator.nymtech.net/api/v1/openapi.json"
        self.api_endpoints_json = "api_endpoints.json"

    def display_results(self, args):
        mode, host, node_df, node_dict, api_data, swagger_data, routing_history = self.collect_all_results(args)
        print(f"Node type = {mode}")
        print(f"Node Identity Key = {args.id}")
        #print(f"Node host = {host}")
        #api_data = self.format_dataframe(api_data)
        print("\n\nNODE RESULTS FROM UNFILTERED QUERY\n")
        self.print_neat_dict(node_dict)
        print(f"\n\nNODE RESULTS FROM {self.api_url.upper()}\n")
        self.print_neat_dict(api_data)
#        print(node_df.T.to_markdown(), "\n")
#        print(api_data.to_markdown(), "\n")
        if swagger_data:
            print(f"\n\nNODE RESULTS FROM SWAGGER PAGE\n")
            self.print_neat_dict(swagger_data)
            print(f"\n\nNODE UPTIME HISTORY\n")
            self.print_neat_dict(routing_history)
#            swagger_data = self.format_dataframe(swagger_data)
#            routing_history = self.format_dataframe(routing_history)
#            print(swagger_data.to_markdown())
#            print(routing_history.to_markdown())

    def collect_all_results(self,args):
        id_key = args.id
        gateways_unfiltered, mixnodes_unfiltered = self.get_unfiltered_data()
        gateways_df = self._json_to_dataframe(gateways_unfiltered)
        gateways_df = self._set_index_to_empty(gateways_df)
        mixnodes_df = self._json_to_dataframe(mixnodes_unfiltered)
        mixnodes_df = self._set_index_to_empty(mixnodes_df)
        mode, node_df, node_dict = self.get_node_df(id_key, gateways_df, mixnodes_df)
        api_data, swagger_data, host, routing_history = self.get_node_data(mode, node_dict, id_key)
        #drop_index = f"/status/gateway/{id_key}/history.history"
        #api_data = api_data.drop(index=drop_index)

        return mode, host, node_df, node_dict, api_data, swagger_data, routing_history

    def get_node_df(self,id_key, gateways_df, mixnodes_df):
        if id_key in mixnodes_df['mixnode_details.bond_information.mix_node.identity_key'].values:

            node_df = mixnodes_df.loc[mixnodes_df['mixnode_details.bond_information.mix_node.identity_key'] == id_key]
            mode = "mixnode"
        elif id_key in gateways_df['gateway_bond.gateway.identity_key'].values:

            node_df = gateways_df.loc[gateways_df['gateway_bond.gateway.identity_key'] == id_key]
            mode = "gateway"
        else:
            print(f"The identity key '{id_key}' does not exist.")

        node_dict = node_df.to_dict()

        return mode, node_df, node_dict

    def get_unfiltered_data(self):
        gateways_unfiltered = r.get(f"{self.api_url}/status/gateways/detailed-unfiltered").json()
        mixnodes_unfiltered = r.get(f"{self.api_url}/status/mixnodes/detailed-unfiltered").json()
        return gateways_unfiltered, mixnodes_unfiltered

    def get_mixnode_data(self, node_df, id_key):
        mix_id = int(node_df["mixnode_details.bond_information.mix_id"])


    def get_node_data(self,mode, node_dict, id_key):
        #endpoint_json = self.get_api_endpoints()
        identity = id_key
        endpoint_json = self.api_endpoints_json
        #node_series = node_series.reset_index(drop=True)
        with open(endpoint_json, "r") as f:
            dicts = json.load(f)
            enpoints = dicts[mode]
            swagger = dicts["swagger"]
        api_data = {}
        swagger_data = {}
        routing_history = {}
        if mode == "gateway":
            host = node_dict["gateway_bond.gateway.host"][""]
                        #api_data["API ENPOINTS"] = "RESPONSE"

            for key in enpoints:
                endpoint = key.replace("{identity}", identity)
                url = f"{self.api_url}{endpoint}"
                value = r.get(url).json()
                api_data[endpoint] = value
            routing_history = api_data[f"/status/gateway/{identity}/history"]["history"]
            del api_data[f"/status/gateway/{identity}/history"]["history"]
            #swagger_data["SWAGGER ENDPOINTS"] = "RESPONSE"
            for key in swagger:
                swagger_url = f"https://{host}:8080/api/v1{key}"
                value = r.get(url).json()
                swagger_data[key] = value
        elif mode == "mixnode":
            mix_id = int(node_series["mixnode_details.bond_information.mix_id"])
        else:
            print(f"The mode type {mode} is not recognized!")
            sys.exit(-1)
        host = str(host)
        return api_data, swagger_data, host, routing_history


#    def get_api_endpoints(self):
#        endpoint_json = r.get(self.api_existing_endpoints_url).json()
#        return endpoint_json

    def _set_index_to_empty(self, df):
        index_len = pd.RangeIndex(len(df.index))
        new_index = []
        for x in index_len:
            x = ""
            new_index.append(x)
        df.index = new_index
        return df


    def format_dataframe(self, df):
        #df = pd.DataFrame(df)
        df = self._json_to_dataframe(df)
        df = df.T
        #df.columns = ["API ENDPOINT", "RESULTS"]
        return df

    def print_neat_dict(self, dictionary, indent=4):
        neat_dictionary = self._json_neat_format(dictionary)
        print(neat_dictionary)

    def _json_neat_format(self,dictionary,indent=4):
        dictionary = json.dumps(dictionary, indent = indent)
        return dictionary

    def _json_to_dataframe(self,json):
        df = pd.json_normalize(json)
        return df

class ArgParser:

    def __init__(self):
        """init for parser"""
        self.functions = MainFunctions()

    def parser_main(self):
        """Main function initializing ArgumentParser, storing arguments and executing commands."""
        # Top level parser
        parser = argparse.ArgumentParser(
                prog= "Nym-node API check",
                description='''Run through all endpoints and print results.'''
            )
        parser.add_argument("-V","--version", action="version", version='%(prog)s 0.1.0')

        # sub-command parsers
        subparsers = parser.add_subparsers(help="{subcommand}[-h] shows all the options")
        parser_check = subparsers.add_parser('check',help='Run with node identity key', aliases=['c','C'])

        # check - arguments
        parser_check.add_argument("id", help="supply nym-node identity key")
        parser_check.set_defaults(func=self.functions.display_results)

        args = parser.parse_args()

        try:
            args.func(args)
        except AttributeError as e:
            msg = f"{e}.\nPlease run __file__ --help"
            self.panic(msg)


    def panic(self,msg):
        """Error message print"""
        print(f"error: {msg}", file=sys.stderr)
        sys.exit(-1)

if __name__ == '__main__':
    node_check = ArgParser()
    node_check.parser_main()
