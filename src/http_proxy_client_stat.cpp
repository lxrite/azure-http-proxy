/*
 *    http_proxy_client_stat.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <numeric>

#include "http_proxy_client_stat.hpp"

namespace azure_proxy {

http_proxy_client_stat::http_proxy_client_stat() :
    upgoing_bytes_in(0),
    upgoing_bytes_out(0),
    downgoing_bytes_in(0),
    downgoing_bytes_out(0),
    upgoing_rate_in(0),
    upgoing_rate_out(0),
    downgoing_rate_in(0),
    downgoing_rate_out(0),
    upgoing_speed_in(0),
    upgoing_speed_out(0),
    downgoing_speed_in(0),
    downgoing_speed_out(0),
    total_bytes_of_upgoing_in(0),
    total_bytes_of_upgoing_out(0),
    total_bytes_of_downgoing_in(0),
    total_bytes_of_downgoing_out(0),
    current_connections(0)
{}

std::uint32_t http_proxy_client_stat::increase_current_connections()
{
    return this->current_connections.fetch_add(1, std::memory_order_acq_rel) + 1;
}

std::uint32_t http_proxy_client_stat::decrease_current_connections()
{
    return this->current_connections.fetch_sub(1, std::memory_order_acq_rel) - 1;
}

void http_proxy_client_stat::on_upgoing_recv(std::uint32_t bytes)
{
    this->total_bytes_of_upgoing_in.fetch_add(bytes, std::memory_order_acq_rel);
    this->upgoing_bytes_in.fetch_add(bytes, std::memory_order_acq_rel);
}

void http_proxy_client_stat::on_upgoing_send(std::uint32_t bytes)
{
    this->total_bytes_of_upgoing_out.fetch_add(bytes, std::memory_order_acq_rel);
    this->upgoing_bytes_out.fetch_add(bytes, std::memory_order_acq_rel);
}

void http_proxy_client_stat::on_downgoing_recv(std::uint32_t bytes)
{
    this->total_bytes_of_downgoing_in.fetch_add(bytes, std::memory_order_acq_rel);
    this->downgoing_bytes_in.fetch_add(bytes, std::memory_order_acq_rel);
}

void http_proxy_client_stat::on_downgoing_send(std::uint32_t bytes)
{
    this->total_bytes_of_downgoing_out.fetch_add(bytes, std::memory_order_acq_rel);
    this->downgoing_bytes_out.fetch_add(bytes, std::memory_order_acq_rel);
}

std::uint64_t http_proxy_client_stat::get_upgoing_total_bytes_recv() const
{
    return this->total_bytes_of_upgoing_in.load(std::memory_order_acquire);
}

std::uint64_t http_proxy_client_stat::get_upgoing_total_bytes_send() const
{
    return this->total_bytes_of_upgoing_out.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_upgoing_rate_recv() const
{
    return this->upgoing_rate_in.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_upgoing_rate_send() const
{
    return this->upgoing_rate_out.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_upgoing_speed_recv() const
{
    return this->upgoing_speed_in.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_upgoing_speed_send() const
{
    return this->upgoing_speed_out.load(std::memory_order_acquire);
}

std::uint64_t http_proxy_client_stat::get_downgoing_total_bytes_recv() const
{
    return this->total_bytes_of_downgoing_in.load(std::memory_order_acquire);
}

std::uint64_t http_proxy_client_stat::get_downgoing_total_bytes_send() const
{
    return this->total_bytes_of_downgoing_out.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_downgoing_rate_recv() const
{
    return this->downgoing_rate_in.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_downgoing_rate_send() const
{
    return this->downgoing_rate_out.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_downgoing_speed_recv() const
{
    return this->downgoing_speed_in.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_downgoing_speed_send() const
{
    return this->downgoing_speed_out.load(std::memory_order_acquire);
}

std::uint32_t http_proxy_client_stat::get_current_connections() const
{
    return this->current_connections.load(std::memory_order_acquire);
}

void http_proxy_client_stat::start_stat(boost::asio::io_service& io_service)
{
    auto sp_timer = std::make_shared<boost::asio::basic_waitable_timer<std::chrono::steady_clock>>(io_service);
    sp_timer->expires_from_now(std::chrono::seconds(1));
    sp_timer->async_wait([this, sp_timer](const boost::system::error_code& error) {
        this->callback(error, sp_timer);
    });
}

void http_proxy_client_stat::callback(const boost::system::error_code& error, std::shared_ptr<boost::asio::basic_waitable_timer<std::chrono::steady_clock>> sp_timer)
{
    if (error != boost::asio::error::operation_aborted) {
        std::uint32_t up_rate_in = this->upgoing_bytes_in.exchange(0, std::memory_order_acq_rel);
        std::uint32_t up_rate_out = this->upgoing_bytes_out.exchange(0, std::memory_order_acq_rel);
        std::uint32_t down_rate_in = this->downgoing_bytes_in.exchange(0, std::memory_order_acq_rel);
        std::uint32_t down_rate_out =  this->downgoing_bytes_out.exchange(0, std::memory_order_acq_rel);

        this->upgoing_rate_in.store(up_rate_in, std::memory_order_release);
        this->upgoing_rate_out.store(up_rate_out, std::memory_order_release);
        this->downgoing_rate_in.store(down_rate_in, std::memory_order_release);
        this->downgoing_rate_out.store(down_rate_out, std::memory_order_release);

        this->upgoing_rate_in_queue.push_back(up_rate_in);
        while (this->upgoing_rate_in_queue.size() > 5) {
            this->upgoing_rate_in_queue.pop_front();
        }

        this->upgoing_rate_out_queue.push_back(up_rate_out);
        while (this->upgoing_rate_out_queue.size() > 5) {
            this->upgoing_rate_out_queue.pop_front();
        }

        this->downgoing_rate_in_queue.push_back(down_rate_in);
        while (this->downgoing_rate_in_queue.size() > 5) {
            this->downgoing_rate_in_queue.pop_front();
        }

        this->downgoing_rate_out_queue.push_back(down_rate_out);
        while (this->downgoing_rate_out_queue.size() > 5) {
            this->downgoing_rate_out_queue.pop_front();
        }

        auto calc_speed = [](const std::deque<std::uint32_t>& queue) -> std::uint32_t {
            return std::accumulate(queue.begin(), queue.end(), 0) / queue.size();
        };

        this->upgoing_speed_in.store(calc_speed(this->upgoing_rate_in_queue), std::memory_order_release);
        this->upgoing_speed_out.store(calc_speed(this->upgoing_rate_out_queue), std::memory_order_release);
        this->downgoing_speed_in.store(calc_speed(this->downgoing_rate_in_queue), std::memory_order_release);
        this->downgoing_speed_out.store(calc_speed(this->downgoing_rate_out_queue), std::memory_order_release);

        sp_timer->expires_from_now(std::chrono::seconds(1));
        sp_timer->async_wait([this, sp_timer](const boost::system::error_code& error) {
            this->callback(error, sp_timer);
        });
    }
}

http_proxy_client_stat& http_proxy_client_stat::get_instance()
{
    static http_proxy_client_stat instance;
    return instance;
}

} // namespace azure_proxy
