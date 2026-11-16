"""Theme-aware presentation shared by charts and the dashboard."""
import streamlit as st

ACCENTS = ["#38BDAA", "#778BFA", "#E7AF58", "#EF778B", "#62B3E9", "#A98AE8"]


def dark():
    return st.context.theme.type == "dark"


def style_chart(fig, height=320):
    grid = "rgba(140,160,190,.14)"
    # Let Streamlit recolor fonts and chart surfaces immediately when the user
    # changes the native theme; fixed light/dark colors would become stale.
    fig.update_layout(template=None,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Arial, sans-serif", size=12),
        colorway=ACCENTS, margin=dict(l=8,r=22,t=16,b=12), height=height,
        legend=dict(orientation="h", y=-.2), hoverlabel=dict(font_size=12),
        transition=dict(duration=180))
    fig.update_xaxes(showline=False, zeroline=False, gridcolor=grid)
    fig.update_yaxes(showline=False, zeroline=False, gridcolor=grid)
    return fig


def install_style():
    st.markdown('''<style>
    .block-container {max-width:1440px; padding-top:2.2rem; padding-bottom:3rem;}
    h1 {font-size:2rem!important; letter-spacing:-.045em; font-weight:750!important;}
    h2 {font-size:1.35rem!important; letter-spacing:-.025em;}
    h3 {font-size:1.05rem!important; letter-spacing:-.015em;}
    [data-testid="stMetric"] {border:1px solid rgba(128,151,181,.21); border-radius:14px; padding:16px 19px;}
    [data-testid="stMetricLabel"] {font-size:.82rem; opacity:.76;}
    [data-testid="stMetricValue"] {font-size:1.85rem; font-weight:650; letter-spacing:-.04em;}
    [data-testid="stVerticalBlockBorderWrapper"] {border-radius:14px;}
    [data-testid="stDataFrame"] {border:1px solid rgba(128,151,181,.15); border-radius:12px; overflow:hidden;}
    [data-baseweb="tab-list"] {gap:1.2rem; border-bottom:1px solid rgba(128,151,181,.2);}
    [data-baseweb="tab"] {padding:13px 2px; font-weight:600;}
    [data-testid="stCode"] {border:1px solid rgba(128,151,181,.18); border-radius:12px;}
    div[data-testid="stAlert"] {border-radius:12px;}
    button, input, [data-baseweb="select"] {transition:border-color .15s ease, background-color .15s ease;}
    @media(max-width:850px) {
      .st-key-traffic_visuals [data-testid="stHorizontalBlock"] {flex-wrap:wrap;}
      .st-key-traffic_visuals [data-testid="stColumn"] {min-width:100%; flex:1 1 100%;}
    }
    </style>''', unsafe_allow_html=True)
