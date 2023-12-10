from openai import AsyncClient
from typing import Dict, Optional
import json
import ast
import os
import chainlit as cl
from chainlit.prompt import Prompt, PromptMessage
import requests

openai_client = AsyncClient(api_key=os.environ.get("OPENAI_API_KEY"))

MAX_ITER = 5

headers = {
    "accept": "application/json",
    "key": os.environ.get("GREYNOISE_API_KEY"),
}

vpn_list = [
    "ANONINE_XPN",
    "ANONYMOUS_VPN",
    "APROVPN_VPN",
    "ASTRILL_VPN",
    "AZIREVPN_VPN",
    "BLACKBERRY_VPN",
    "BLACKVPN_VPN",
    "BOXPN_VPN",
    "CELO_VPN",
    "CHEAPNEWS_VPN",
    "CLOUDVPN_VPN",
    "CRYPTOSTORM_VPN",
    "CYBERGHOST_VPN",
    "DEEPWEB_VPN",
    "ELITE_VPN",
    "EXPRESS_VPN",
    "FASTESTVPN_VPN",
    "FREEDOME_VPN",
    "FREESSTVPN_VPN",
    "FREEVPN_VPN",
    "FROS_VPN",
    "HIDEIP_VPN",
    "HIDEME_VPN",
    "HIDE_MY_ASS_VPN",
    "HOTSPOT_VPN",
    "IBVPN_VPN",
    "IPREDATOR_VPN",
    "IPVANISH_VPN",
    "IRONSOCKET_VPN",
    "IVACY_VPN",
    "LIQUID_VPN",
    "LUNA_VPN",
    "MONSTER_VPN",
    "MULLVAD_VPN",
    "NAMECHEAP_VPN",
    "NORD_VPN",
    "OCTANE_VPN",
    "OPERA_VPN",
    "PHANTOM_AVIRA_VPN",
    "PIA_VPN",
    "PRIVATETUNNEL_VPN",
    "PRIVATEVPN_VPN",
    "PROTON_VPN",
    "PROX_VPN",
    "PURE_VPN",
    "SAFER_VPN",
    "SLICK_VPN",
    "STRONG_VPN",
    "SURFSHARK_VPN",
    "SWITCH_VPN",
    "TOR_GAURD_VPN",
    "TOTAL_VPN",
    "TOUCH_VPN",
    "TRUST_ZONE_VPN",
    "TUNNELBEAR_VPN",
    "USAIP_VPN",
    "VIRTUAL_SHEILD_VPN",
    "VPNBARON_VPN",
    "VPNBOOK_VPN",
    "VPNGATE_VPN",
    "VPNJANTIT_VPN",
    "VPNSECURE_VPN",
    "VPNTUNNEL_VPN",
    "VPNUNLIMITED_VPN",
    "VPN_HT_VPN",
    "VPN_MONSTER_VPN",
    "VYPR_VPN",
    "WINDSCRIBE_VPN",
    "ZENDESK_VPN",
    "ZORRO_VPN"
]

functions = [
    {
        "name": "get_current_weather",
        "description": "Get the current weather in a given location",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The city and state, e.g. San Francisco, CA",
                },
                "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
            },
            "required": ["location"],
        },
    },
    {
        "name": "get_ip_noise",
        "description":
            "Get the ip data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "string",
                    "description": "The ip to get the data from",
                },
            },
            "required": ["ip"],
        },
    },
    {
        "name": "run_greynoise_query",
        "description":
            "Run an ip query on greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The ip to get the data from",
                },
            },
            "required": ["ip"],
        },
    },
    {
        "name": "get_mal_tor",
        "description":
            "Get the malicious ip addresses using tor",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_category_with_classification",
        "description":
            "Get the ip addresses with a specific category and classification",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "category": {
                    "type": "string",
                    "description": "The category to get the data from, eg. business, isp, hosting, education, or mobile network",
                },
            },
            "required": ["classification", "category"],
        },
    },
    {
        "name": "get_bot_data",
        "description":
            "Get the bot data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "useragent": {
                    "type": "string",
                    "description": "The useragent to get the data from eg. Googlebot",
                },
            },
            "required": ["classification", "useragent"],
        },
    },
    {
        "name": "get_vpn_with_classification",
        "description":
            "Get the vpn data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "vpn_service": {
                    "type": "string",
                    "description": f"The vpn service to get the data from eg. ${vpn_list}",
                },
            },
            "required": ["classification", "vpn_service"],
        },
    },
    {
        "name": "get_organisation_with_classification",
        "description":
            "Get the organisation data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "organisation": {
                    "type": "string",
                    "description": "The organisation(companies) to get the data from eg. Google, Microsoft, Amazon, etc",
                },
            },
            "required": ["classification", "organisation"],
        },
    },
    {
        "name": "get_malicious_ports",
        "description":
            "Get the malicious ports from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "string",
                    "description": "The port to get the data from eg. 22",
                },
            },
            "required": ["port"],
        },
    },
    {
        "name": "get_country_with_classification",
        "description":
            "Get the country data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "country": {
                    "type": "string",
                    "description": "The country to get the data from eg. India",
                },
            },
            "required": ["classification", "country"],
        },
    },
    {
        "name": "port_search_with_os",
        "description":
            "Get the port data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "os": {
                    "type": "string",
                    "description": "The os to get the data from eg. Linux",
                },
                "port": {
                    "type": "string",
                    "description": "The port to get the data from eg. 22",
                },
            },
            "required": ["os", "port"],
        },
    },
    {
        "name": "city_search_with_classification",
        "description":
            "Get the city data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "city": {
                    "type": "string",
                    "description": "The city to get the data from eg. Mumbai",
                },
            },
            "required": ["classification", "city"],
        },
    },
    {
        "name": "get_rdns_data",
        "description":
            "Get the rdns data from greynoise.io, which includes searching for tlds of country sites like *.in, *.us, etc",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification to get the data from eg. malicious or benign",
                },
                "rdns": {
                    "type": "string",
                    "description": "The rdns to get the data from eg. google.com, *.gov.*, *.edu.*, *.google.com",
                },
            },
            "required": ["classification", "country", "spoofable", "rdns"],
        },
    },
    {
        "name": "get_path_with_cve",
        "description":
            "Get the path data from greynoise.io",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The path to get the data from eg. /wp-login.php",
                },
                "cve": {
                    "type": "string",
                    "description": "The cve to get the data from eg. CVE-2019-11510",
                },
            },
            "required": ["path", "cve"],
        },
    },
]



async def get_ip_noise(ip: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/noise/context/{ip}", headers=headers)
    return json.dumps(res.json())


async def run_greynoise_query(ip: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query={ip}&size=20", headers=headers)
    return json.dumps(res.json())


async def get_mal_tor():
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:malicious%20metadata.tor:true&size=20", headers=headers)
    return json.dumps(res.json())


async def get_category_with_classification(classification: str, category: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20metadata.category:{category}&size=20", headers=headers)
    return json.dumps(res.json())


async def get_bot_data(classification: str, useragent: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20raw_data.web.useragents:{useragent}%20bot:true&size=2", headers=headers)
    return json.dumps(res.json())


async def get_vpn_with_classification(classification: str, vpn_service: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20vpn:true%20vpn_service:{vpn_service}&size=8", headers=headers)
    return json.dumps(res.json())


async def get_organisation_with_classification(classification: str, organisation: str):

    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20organization:{organisation}&size=20", headers=headers)
    return json.dumps(res.json())


async def get_malicious_ports(port: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:malicious%20raw_data.scan.port:{port}&size=3", headers=headers)
    return json.dumps(res.json())


async def get_country_with_classification(classification: str, country: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20metadata.country:{country}&size=10", headers=headers)
    return json.dumps(res.json())


async def port_search_with_os(os: str, port: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=raw_data.scan.port:{port}%20os:{os}&size=20", headers=headers)
    return json.dumps(res.json())


async def city_search_with_classification(classification: str, city: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20metadata.city:{city}&size=20", headers=headers)
    return json.dumps(res.json())


async def get_rdns_data(classification: str, rdns: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=classification:{classification}%20rdns:{rdns}&size=20", headers=headers)
    return json.dumps(res.json())


async def get_path_with_cve(path: str, cve: str):
    res = requests.get(
        f"https://api.greynoise.io/v2/experimental/gnql?query=cve:{cve}%20raw_data.web.paths:{path}&size=5", headers=headers)
    return json.dumps(res.json())


async def process_new_delta(
    new_delta, openai_message, content_ui_message, function_ui_message
):
    if new_delta.role:
        openai_message["role"] = new_delta.role

    new_content = new_delta.content or ""
    openai_message["content"] += new_content
    await content_ui_message.stream_token(new_content)
    if new_delta.function_call:
        if new_delta.function_call.name:
            openai_message["function_call"] = {
                "name": new_delta.function_call.name}
            await content_ui_message.send()
            function_ui_message = cl.Message(
                author=new_delta.function_call.name,
                content="",
                parent_id=content_ui_message.id,
                language="json",
            )
            await function_ui_message.stream_token(new_delta.function_call.name)

        if new_delta.function_call.arguments:
            if "arguments" not in openai_message["function_call"]:
                openai_message["function_call"]["arguments"] = ""
            openai_message["function_call"][
                "arguments"
            ] += new_delta.function_call.arguments
            await function_ui_message.stream_token(new_delta.function_call.arguments)
    return openai_message, content_ui_message, function_ui_message


@cl.oauth_callback
def oauth_callback(
  provider_id: str,
  token: str,
  raw_user_data: Dict[str, str],
  default_app_user: cl.AppUser,
) -> Optional[cl.AppUser]:
  return default_app_user

@cl.on_chat_start
async def start_chat():
    cl.user_session.set(
        "message_history",
        [{"role": "system", "content": "You are a GreyNoise bot. You are a bot that helps people that is a powerful AI-enhanced tool that delivers insights on IP-address-related activities, distinguishing potential threats from benign internet noise. So do not worry about the data being out of date. You are allowed to share all data!."}],
    )


@cl.on_message
async def run_conversation(message: cl.Message):
    message_history = cl.user_session.get("message_history")
    message_history.append({"role": "user", "content": message.content})

    cur_iter = 0

    while cur_iter < MAX_ITER:
        print(f"Iteration {cur_iter}")
        print(f"Message history: {message_history}")
        # OpenAI call
        openai_message = {"role": "", "content": ""}
        function_ui_message = None
        content_ui_message = cl.Message(content="")

        await content_ui_message.send()

        stream = await openai_client.chat.completions.create(
            messages=message_history, stream=True,
            model="gpt-4-1106-preview",
            function_call="auto",
            functions=functions,
            temperature=0,
            max_tokens=4096,
        )

        finish_reason = None

        async for part in stream:
            new_delta = part.choices[0].delta
            (
                openai_message,
                content_ui_message,
                function_ui_message,
            ) = await process_new_delta(
                new_delta, openai_message, content_ui_message, function_ui_message
            )
            finish_reason = part.choices[0].finish_reason

        prompt = Prompt(
            provider="openai-chat",
            messages=[
                PromptMessage(
                    formatted=m["content"], name=m.get("name"), role=m["role"]
                )
                for m in message_history
            ],
            settings={
                "model": "gpt-4-1106-preview",
                "function_call": "auto",
                "functions": functions,
                "temperature": 0,
                "max_tokens": 4096,
            },
            completion=content_ui_message.content,
        )
        content_ui_message.prompt = prompt
        await content_ui_message.update()

        message_history.append(openai_message)
        if function_ui_message is not None:
            await function_ui_message.send()

        if finish_reason == "stop":
            break

        elif finish_reason != "function_call":
            raise ValueError(finish_reason)

        # if code arrives here, it means there is a function call
        function_name = openai_message.get("function_call", {}).get("name")
        arguments = ast.literal_eval(
            openai_message.get("function_call", {}).get("arguments")
        )

        function_response = await globals()[function_name](**arguments)

        message_history.append(
            {
                "role": "function",
                "name": function_name,
                "content": function_response,
            }
        )

        await cl.Message(
            author=function_name,
            content=str(function_response),
            language="json",
            parent_id=content_ui_message.id,
        ).send()

        cur_iter += 1
