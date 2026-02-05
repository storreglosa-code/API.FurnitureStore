using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitoreStore.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class OrdersController : ControllerBase
    {
        private readonly IOrdersService _ordersService;

        public OrdersController(IOrdersService ordersService)
        {
            _ordersService = ordersService;
        }

        [HttpGet]
        public async Task<IEnumerable<Order>> Get() 
        {
            return await _ordersService.GetAllAsync();
        }

        [HttpGet ("{id}")]
        public async Task<IActionResult> GetDetails(int id)
        { 
            var order = await _ordersService.GetByIdAsync(id);
            if (order == null) 
                return NotFound();
            return Ok(order);
        }

        [HttpPost]
        public async Task<IActionResult> Post(Order order) 
        {
            if (order == null) return NotFound();
            if (order.OrderDetails == null)
                return BadRequest("Order should have at least one detail");

            await _ordersService.CreateAsync(order);
            return CreatedAtAction("Post", order.Id, order);
        }

        [HttpPut]
        public async Task<IActionResult> Put(Order order)
        {
            if (order == null) return NotFound();
            if (order.Id <= 0) return NotFound();

            await _ordersService.UpdateAsync(order);
            return NoContent();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(Order order)
        { 
            if (order == null) return NotFound();

            var existingOrder = await _ordersService.GetByIdAsync(order.Id);
            if (existingOrder == null) return NotFound();

            await _ordersService.DeleteAsync(existingOrder.Id);
            return NoContent();
        }
    }
}
