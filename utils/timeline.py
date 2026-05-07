"""
utils/timeline.py
Генерация временно́й шкалы инцидентов: плотность атак по времени.
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from typing import Optional


# ------------------------------------------------------------------ #
#  Генерация временны́х меток                                         #
# ------------------------------------------------------------------ #

def assign_timestamps(df: pd.DataFrame,
                       time_col: Optional[str] = None,
                       base_time: Optional[datetime] = None,
                       interval_seconds: float = 0.5) -> pd.DataFrame:
    """
    Если в DataFrame нет колонки времени — генерируем синтетические метки.
    Каждой строке присваивается метка с шагом interval_seconds.
    
    Параметры:
        df               — входной DataFrame
        time_col         — имя существующей колонки времени (если есть)
        base_time        — начало шкалы (по умолчанию — сейчас минус len(df)*interval)
        interval_seconds — интервал между пакетами в секундах
    
    Возвращает DataFrame с колонкой '_timestamp'.
    """
    result = df.copy()

    # Если колонка уже есть — пробуем её распарсить
    if time_col and time_col in df.columns:
        try:
            result["_timestamp"] = pd.to_datetime(df[time_col], errors="coerce")
            if result["_timestamp"].notna().sum() > 0:
                return result
        except Exception:
            pass

    # Синтетические метки
    if base_time is None:
        base_time = datetime.now() - timedelta(seconds=len(df) * interval_seconds)

    result["_timestamp"] = [
        base_time + timedelta(seconds=i * interval_seconds)
        for i in range(len(df))
    ]
    return result


# ------------------------------------------------------------------ #
#  Построение временно́й шкалы                                        #
# ------------------------------------------------------------------ #

def build_timeline(df: pd.DataFrame,
                   label_col: str = "Result",
                   time_col: str = "_timestamp",
                   freq: str = "5s",
                   accent_color: str = "#00D4FF",
                   template: str = "plotly_dark") -> go.Figure:
    """
    Строит интерактивный график плотности атак по времени (Plotly).
    
    Параметры:
        df           — DataFrame с временны́ми метками и метками классов
        label_col    — колонка с предсказаниями ('Result': 'anomaly'/'normal')
        time_col     — колонка с datetime
        freq         — гранулярность агрегации ('1s', '5s', '1min', ...)
        accent_color — цвет для аномалий
        template     — тема Plotly
    
    Возвращает Figure.
    """
    if time_col not in df.columns:
        raise ValueError(f"Колонка времени '{time_col}' не найдена.")
    if label_col not in df.columns:
        raise ValueError(f"Колонка меток '{label_col}' не найдена.")

    ts = df.set_index(time_col)

    # Агрегация по времени
    anom_series  = ts[ts[label_col] == "anomaly"].resample(freq).size().rename("anomalies")
    norm_series  = ts[ts[label_col] == "normal"].resample(freq).size().rename("normal")
    total_series = ts.resample(freq).size().rename("total")

    agg = pd.concat([total_series, anom_series, norm_series], axis=1).fillna(0).reset_index()
    agg.columns = ["time", "total", "anomalies", "normal"]

    # Создаём фигуру
    fig = go.Figure()

    # Нормальный трафик (фон)
    fig.add_trace(go.Scatter(
        x=agg["time"], y=agg["normal"],
        name="Нормальный",
        fill="tozeroy",
        line=dict(color="#4CAF50", width=1.5),
        fillcolor="rgba(76, 175, 80, 0.15)",
        hovertemplate="<b>%{x}</b><br>Нормальных: %{y}<extra></extra>",
    ))

    # Аномальный трафик (выделяем)
    fig.add_trace(go.Scatter(
        x=agg["time"], y=agg["anomalies"],
        name="Аномалии",
        fill="tozeroy",
        line=dict(color=accent_color, width=2),
        fillcolor=f"rgba(255, 75, 75, 0.25)",
        hovertemplate="<b>%{x}</b><br>Аномалий: %{y}<extra></extra>",
    ))

    # Отмечаем пики
    if agg["anomalies"].max() > 0:
        peak_row = agg.loc[agg["anomalies"].idxmax()]
        fig.add_vline(
            x=peak_row["time"],
            line_width=1.5,
            line_dash="dash",
            line_color="#FF4B4B",
            annotation_text=f"  Пик: {int(peak_row['anomalies'])} аномалий",
            annotation_font_color="#FF4B4B",
        )

    fig.update_layout(
        template=template,
        title=dict(text="Временна́я шкала инцидентов", font=dict(size=16)),
        xaxis_title="Время",
        yaxis_title="Кол-во событий",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=0, r=0, t=50, b=0),
        height=320,
        hovermode="x unified",
    )

    return fig


def peak_stats(df: pd.DataFrame,
               label_col: str = "Result",
               time_col: str = "_timestamp",
               freq: str = "5s") -> dict:
    """
    Возвращает статистику пиков:
    {
        "peak_time": datetime,
        "peak_count": int,
        "peak_normal": int,
        "total_anomalies": int,
        "total_packets": int,
        "anomaly_rate": float,  — доля аномалий 0..1
        "duration_seconds": float,
    }
    """
    if time_col not in df.columns or label_col not in df.columns:
        return {}

    anomalies = df[df[label_col] == "anomaly"]
    if anomalies.empty:
        return {
            "peak_time": None,
            "peak_count": 0,
            "total_anomalies": 0,
            "total_packets": len(df),
            "anomaly_rate": 0.0,
            "duration_seconds": 0.0,
        }

    ts = df.set_index(time_col)
    anom_agg = ts[ts[label_col] == "anomaly"].resample(freq).size()
    peak_idx  = anom_agg.idxmax()

    duration = (df[time_col].max() - df[time_col].min()).total_seconds()

    return {
        "peak_time":       peak_idx,
        "peak_count":      int(anom_agg.max()),
        "total_anomalies": len(anomalies),
        "total_packets":   len(df),
        "anomaly_rate":    round(len(anomalies) / max(len(df), 1), 4),
        "duration_seconds":round(duration, 1),
    }


def heatmap_by_hour(df: pd.DataFrame,
                    label_col: str = "Result",
                    time_col: str = "_timestamp",
                    template: str = "plotly_dark") -> go.Figure:
    """
    Тепловая карта: атаки по часу суток × минуте.
    Полезна для анализа паттернов атак.
    """
    if time_col not in df.columns:
        return go.Figure()

    anom = df[df[label_col] == "anomaly"].copy()
    if anom.empty:
        return go.Figure()

    anom["hour"]   = anom[time_col].dt.hour
    anom["minute"] = (anom[time_col].dt.minute // 5) * 5  # группируем по 5 мин

    pivot = anom.groupby(["hour", "minute"]).size().unstack(fill_value=0)

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"{m:02d}" for m in pivot.columns],
        y=[f"{h:02d}:00" for h in pivot.index],
        colorscale="Reds",
        hovertemplate="Час: %{y}<br>Минута: %{x}<br>Атак: %{z}<extra></extra>",
    ))

    fig.update_layout(
        template=template,
        title="Тепловая карта атак (час × минута)",
        xaxis_title="Минута",
        yaxis_title="Час суток",
        margin=dict(l=0, r=0, t=40, b=0),
        height=300,
    )

    return fig
