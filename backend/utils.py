"""Server-side helpers. Client bits (timeAgo/tier colors) live in frontend/js/app.js."""
from flask import jsonify


def error_response(message: str, status: int):
    return jsonify({"error": message}), status


TIER_COLORS = {
    "moderator": "text-red-600",
    "expert": "text-orange-600",
    "trusted": "text-blue-600",
    "new": "text-green-600",
    "newcomer": "text-gray-500",
}

TIER_BG_COLORS = {
    "moderator": "bg-red-100 text-red-700",
    "expert": "bg-orange-100 text-orange-700",
    "trusted": "bg-blue-100 text-blue-700",
    "new": "bg-green-100 text-green-700",
    "newcomer": "bg-gray-100 text-gray-700",
}


def get_tier_color(tier: str) -> str:
    return TIER_COLORS.get(tier or "", "text-gray-500")


def get_tier_bg_color(tier: str) -> str:
    return TIER_BG_COLORS.get(tier or "", "bg-gray-100 text-gray-700")
