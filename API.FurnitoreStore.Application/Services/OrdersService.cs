using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Services;

public class OrdersService : IOrdersService
{
    private readonly ApplicationDbContext _context;

    public OrdersService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<Order>> GetAllAsync()
    {
        try
        {
            return await _context.Orders
                                 .Include(o => o.OrderDetails)
                                 .ToListAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error retrieving orders", ex);
        }
    }

    public async Task<Order?> GetByIdAsync(int id)
    {
        try
        {
            return await _context.Orders
                                 .Include(o => o.OrderDetails)
                                 .FirstOrDefaultAsync(o => o.Id == id);
        }
        catch (Exception ex)
        {
            throw new Exception("Error retrieving order", ex);
        }
    }

    public async Task CreateAsync(Order order)
    {
        try
        {
            if (order == null) throw new ArgumentNullException(nameof(order));
            if (order.OrderDetails == null || order.OrderDetails.Count == 0)
                throw new ArgumentException("Order should have at least one detail", nameof(order));

            await _context.Orders.AddAsync(order);
            await _context.OrderDetails.AddRangeAsync(order.OrderDetails);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error creating order", ex);
        }
    }

    public async Task UpdateAsync(Order order)
    {
        try
        {
            if (order == null) throw new ArgumentNullException(nameof(order));
            if (order.Id <= 0) throw new ArgumentException("Invalid order id", nameof(order));

            var existingOrder = await _context.Orders
                                              .Include(o => o.OrderDetails)
                                              .FirstOrDefaultAsync(o => o.Id == order.Id);

            if (existingOrder == null)
                throw new Exception("Order not found.");

            existingOrder.OrderNumber = order.OrderNumber;
            existingOrder.OrderDate = order.OrderDate;
            existingOrder.DeliveryDate = order.DeliveryDate;
            existingOrder.Observaciones = order.Observaciones;
            // keep client relationship as original code commented it out

            // replace details
            _context.OrderDetails.RemoveRange(existingOrder.OrderDetails);
            _context.Orders.Update(existingOrder);
            _context.OrderDetails.AddRange(order.OrderDetails);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error updating order", ex);
        }
    }

    public async Task DeleteAsync(int id)
    {
        try
        {
            var existingOrder = await _context.Orders
                                              .Include(o => o.OrderDetails)
                                              .FirstOrDefaultAsync(o => o.Id == id);

            if (existingOrder == null)
                throw new Exception("Order not found.");

            _context.OrderDetails.RemoveRange(existingOrder.OrderDetails ?? new List<OrderDetail>());
            _context.Orders.Remove(existingOrder);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error deleting order", ex);
        }
    }
}
